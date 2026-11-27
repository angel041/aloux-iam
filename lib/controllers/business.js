const mongoose = require("mongoose");
const Business = require("../models/Business");
const Company = require("../models/Company");
const User = require("../models/User");
const utils = require("../config/utils");
const providers = require("../providers");
const errorController = require("../config/utils");
const { resolveGkey } = require("../config/utils");

const self = module.exports;

// Alcance de datos: Propietario ve todo; el resto, solo sus propios negocios (mismo
// criterio que access.js en copla: el usuario accede a su _business, el Propietario a todos).
// Acceso total: por la marca isOwner de la función o por el nombre histórico.
// Antes se miraba solo _functions[0], así que con varias funciones el propietario
// no se reconocía si no era la primera.
const OWNER_FUNCTION_NAME = process.env.OWNER_FUNCTION || "Propietario";
const isOwner = (user) =>
  (user?._functions || []).some((fn) => fn?.isOwner === true || fn?.name === OWNER_FUNCTION_NAME);
const idOf = (value) => String((value && value._id) || value);
// Restringe el query a los negocios propios del usuario, salvo que sea Propietario
const scopeToOwn = (query, user) => {
  if (isOwner(user)) return query;
  const own = (user?._business || []).map(idOf);
  return { ...query, _id: { $in: own } };
};

// Negocio sin la llave privada de Google (gkey.key) para responder al cliente
const withoutKey = (business) => {
  const out = business && typeof business.toObject === "function" ? business.toObject() : { ...business };
  if (out.gkey) {
    const { key, ...gkey } = out.gkey;
    out.gkey = gkey;
  }
  return out;
};

self.create = async (req, res) => {
  try {
    req.body.createdAt = new Date().getTime();
    req.body.lastUpdate = req.body.createdAt;
    req.body.status = "Activo";
    const created = [];

    let inheritedGkey = null;
    if (req.body.data?.useCompanyKey && req.body._company) {
      const company = await Company.findOne({ _id: req.body._company }).lean();
      const companyGkey = company?.data?.gkey;
      if (companyGkey?.status) inheritedGkey = companyGkey;
    }

    if (req.body.environment && req.body.environment.length > 1) {
      for (let i in req.body.environment) {
        const business = new Business(req.body);
        business.environment = req.body.environment[i];
        if (inheritedGkey) business.gkey = inheritedGkey;
        await business.save();
        created.push(business._id);
      }
    } else {
      const business = new Business(req.body);
      if (inheritedGkey) business.gkey = inheritedGkey;
      await business.save();
      created.push(business._id);
    }

    // Quien no es Propietario solo ve sus negocios: el que crea queda ligado a él, o no podría volver a encontrarlo.
    // No si lo creó en una compañía ajena: podría heredar su llave y ligarse le daría acceso a esos datos
    const ownCompany = !req.body._company || (req.user?._company || []).map(idOf).includes(idOf(req.body._company));
    if (!isOwner(req.user) && ownCompany) {
      await User.updateOne({ _id: req.user._id }, { $addToSet: { _business: { $each: created } }, $set: { lastUpdate: new Date().getTime() } });
    }

    await res.status(201).send({ _id: created[0], ids: created });
  } catch (error) {
    await errorController.responseError(res, error);
  }
};

self.retrieve = async (req, res) => {
  try {
    const { page, itemsPerPage, search, status, _company, environment, sortBy, sortDesc } = req.query
    const paginate = page != null && itemsPerPage != null
    let query = {}

    if (search) {
      const s = utils.escapeRegex(String(search))
      query.$or = [{ name: { $regex: s, $options: 'i' } }]
    }

    if (status) {
      query.status = status
    }

    if (_company) {
      query._company = _company
    }

    if (environment) {
      query.environment = environment
    }

    query = scopeToOwn(query, req.user)

    if (paginate) {
      const perPage = Math.min(Number(itemsPerPage), 100)
      const count = await Business.countDocuments(query)
      // Columnas ordenables de la tabla de proyectos (sin sortBy: más recientes primero, como antes)
      const sort = utils.sortSpec(sortBy, sortDesc, {
        name: 'name',
        environment: 'environment',
        status: 'status',
        isActive: 'status',
        lastUpdate: 'lastUpdate',
        createdAt: 'createdAt',
        company: '_company.name',
        '_company.name': '_company.name'
      }, { createdAt: -1 })
      const skip = perPage * (Number(page) - 1)
      let items
      if (sort['_company.name']) {
        // Por nombre de la compañía: requiere unirla antes de ordenar
        const match = { ...query }
        if (match._company && mongoose.isValidObjectId(String(match._company))) match._company = new mongoose.Types.ObjectId(String(match._company))
        items = await Business.aggregate([
          { $match: match },
          { $lookup: { from: Company.collection.name, localField: '_company', foreignField: '_id', as: '_company' } },
          { $unwind: { path: '$_company', preserveNullAndEmptyArrays: true } },
          { $sort: sort },
          { $skip: skip },
          { $limit: perPage },
          { $project: { gkey: 0, '_company.gkey': 0, '_company.data.gkey': 0 } }
        ]).collation(utils.sortCollation)
      } else {
        items = await Business.find(query, { gkey: 0 }).populate('_company').sort(sort).collation(utils.sortCollation).skip(skip).limit(perPage).lean()
      }
      const response = await utils.generatePaginationResponse(count, Number(page), perPage, items)
      const { status: _status, ...summaryQuery } = query
      const active = await Business.countDocuments({ ...summaryQuery, status: 'Activo' })
      const inactive = await Business.countDocuments({ ...summaryQuery, status: 'Inactivo' })
      response.summary = { active, inactive, total: active + inactive }
      return res.status(200).send(response)
    }

    const retrieve = await Business.find(query, { gkey: 0 }).populate('_company').lean()
    res.status(200).send(retrieve)
  } catch (error) {
    await errorController.responseError(res, error)
  }
}

self.retrieveByCompany = async (req, res) => {
  try {
    // Las compañías pedidas también se recortan a las propias; si no, cualquier usuario autenticado
    // podía pasar cualquier _id de compañía en el body y ver sus negocios sin tener acceso a ella.
    let companies = Array.isArray(req.body.companies) ? req.body.companies : [];
    if (!isOwner(req.user)) {
      const own = (req.user?._company || []).map(idOf);
      companies = companies.filter((id) => own.includes(idOf(id)));
    }
    const retrieve = await Business.find(
      { _company: { $in: companies } },
      { name: 1, _company: 1, environment: 1 }
    )
      .populate("_company")
      .lean();
    res.status(200).send(retrieve);
  } catch (error) {
    await errorController.responseError(res, error);
  }
};

self.retrieveMy = async (req, res) => {
  try {
    let query = {};
    if (!isOwner(req.user)) {
      query = { _id: req.user._business };
    }
    const retrieve = await Business.find(query, {
      name: 1,
      id: 1,
      environment: 1,
    }).lean();
    res.status(200).send(retrieve);
  } catch (error) {
    await errorController.responseError(res, error);
  }
};

self.retrieveMyCompany = async (req, res) => {
  try {
    let query = {
      _id: req.user._business,
      _company: req.params.COMPANY_ID,
    };
    const retrieve = await Business.find(query, { "gkey.key": 0 }).lean();
    res.status(200).send(retrieve);
  } catch (error) {
    await errorController.responseError(res, error);
  }
};

self.detail = async (req, res) => {
  try {
    // No se devuelve 403 (revelaría que el negocio existe): un negocio ajeno responde
    // igual que uno inexistente. No se reusa scopeToOwn porque pisaría el _id pedido
    // en vez de combinarlo con el de los propios.
    if (!isOwner(req.user) && !(req.user?._business || []).map(idOf).includes(idOf(req.params.BUSINESS_ID))) {
      throw {
        code: 404,
        title: "No se encontro el elemento",
        detail: "No existe el negocio seleccionado",
        suggestion: "Revisa que el negocio exista",
      };
    }
    const detail = await Business.findOne(
      {
        _id: req.params.BUSINESS_ID,
      },
      { "gkey.key": 0 }
    )
      .populate("_company")
      .lean();
    if (!detail) {
      throw {
        code: 404,
        title: "No se encontro el elemento",
        detail: "No existe el negocio seleccionado",
        suggestion: "Revisa que el negocio exista",
      };
    }
    res.status(200).send(detail);
  } catch (error) {
    await errorController.responseError(res, error);
  }
};

self.update = async (req, res) => {
  try {
    const payload = errorController.pickFromSchema(Business, req.body);
    payload.lastUpdate = new Date().getTime();
    const update = await Business.updateOne(
      { _id: req.params.BUSINESS_ID },
      { $set: payload }
    );
    res.status(202).send(update);
  } catch (error) {
    await errorController.responseError(res, error);
  }
};

self.delete = async (req, res) => {
  try {
    let business = await Business.findOne({
      _id: req.params.BUSINESS_ID,
    }).lean();

    if (!business) {
      throw {
        code: 404,
        title: "No se encontro el elemento",
        detail: "No se encontro el negocio",
        suggestion: "Verifica su existencia",
      };
    }

    await Business.deleteOne({
      _id: req.params.BUSINESS_ID,
    });

    res.status(200).send("Success");
  } catch (error) {
    await errorController.responseError(res, error);
  }
};

self.picture = async (req, res) => {
  try {
    let business = await Business.findOne({ _id: req.params.BUSINESS_ID });

    const imgUrl = await providers.storage()?.upload(
      "business/picture-" + req.params.BUSINESS_ID,
      req.files.picture
    );

    business.imgUrl = imgUrl;
    const updateBusiness = await business.save();

    res.status(202).send(withoutKey(updateBusiness));
  } catch (error) {
    errorController.responseError(res, error);
  }
};

self.favicon = async (req, res) => {
  try {
    let business = await Business.findOne({ _id: req.params.BUSINESS_ID });

    const faviconUrl = await providers.storage()?.upload(
      "business/favicon-" + req.params.BUSINESS_ID,
      req.files.favicon
    );

    business.faviconUrl = faviconUrl;
    const updateBusiness = await business.save();

    res.status(202).send(withoutKey(updateBusiness));
  } catch (error) {
    errorController.responseError(res, error);
  }
};

self.identity = async (req, res) => {
  try {
    const detail = await Business.findOne(
      {
        id: req.params.ID,
      },
      { name: 1, imgUrl: 1, faviconUrl: 1 }
    ).lean();
    if (!detail) {
      throw {
        code: 404,
        title: "No se encontro el elemento",
        detail: "No existe el negocio seleccionado",
        suggestion: "Revisa que el negocio exista",
      };
    }
    delete detail._id;
    res.status(200).send(detail);
  } catch (error) {
    await errorController.responseError(res, error);
  }
};

self.setUseCompanyKey = async (req, res) => {
  try {
    const business = await Business.findOne({ _id: req.params.BUSINESS_ID }).lean();
    if (!business) throw { code: 404, title: "No encontrado", detail: "No existe el negocio" };

    await Business.updateOne(
      { _id: req.params.BUSINESS_ID },
      {
        $unset: { gkey: "" },
        $set: {
          "data.useCompanyKey": false,
          lastUpdate: new Date().getTime(),
        },
      }
    );

    res.status(202).send({ ok: true });
  } catch (error) {
    await errorController.responseError(res, error);
  }
};

self.inheritKey = async (req, res) => {
  try {
    const business = await Business.findOne({ _id: req.params.BUSINESS_ID })
      .populate("_company")
      .lean();
    if (!business) throw { code: 404, title: "No encontrado", detail: "No existe el negocio" };

    const companyGkey = business._company?.data?.gkey;
    if (!companyGkey?.status) throw {
      code: 400,
      title: "Sin llave",
      detail: "La organización no tiene una llave de Google Cloud configurada",
    };

    await Business.updateOne(
      { _id: req.params.BUSINESS_ID },
      {
        $set: {
          gkey: companyGkey,
          "data.useCompanyKey": true,
          lastUpdate: new Date().getTime(),
        },
      }
    );

    res.status(202).send({ ok: true });
  } catch (error) {
    await errorController.responseError(res, error);
  }
};