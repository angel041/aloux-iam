// Funciones compuestas ("roles"): una función con kind: "role" no lleva permisos propios, se arma
// marcando otras funciones en _functions. Sus _permissions y _menus son la unión de los de esas.
//
// Se resuelve al guardar, no al leer: así el resto de la plataforma (middleware, getPermission,
// privilegeGuard) sigue viendo una función normal con su lista de permisos, y nada más cambia.
//
// Opcional por diseño: sin kind: "role" nada de esto corre, y los proyectos que no usen roles
// se comportan exactamente igual que antes.
const Functions = require("../models/Functions");

const self = module.exports;

const idOf = (value) => String((value && value._id) || value);

// Permisos y menús que resultan de componer las funciones indicadas
self.composeFrom = async (functionIds = []) => {
  const ids = [...new Set((functionIds || []).map(idOf).filter(Boolean))];
  if (!ids.length) return { _permissions: [], _menus: [] };

  const partes = await Functions.find(
    { _id: { $in: ids }, status: "Activo" },
    { _permissions: 1, _menus: 1, kind: 1 },
  ).lean();

  const permisos = new Map();
  const menus = new Map();
  for (const parte of partes) {
    for (const p of parte._permissions || []) permisos.set(idOf(p), p);
    for (const m of parte._menus || []) menus.set(idOf(m), m);
  }
  return { _permissions: [...permisos.values()], _menus: [...menus.values()] };
};

// Un rol no puede contener otro rol: evita ciclos y mantiene la composición en un solo nivel,
// que es lo que hace falta y lo único que se puede recalcular sin ambigüedad
self.assertNoNestedRoles = async (functionIds = []) => {
  const ids = [...new Set((functionIds || []).map(idOf).filter(Boolean))];
  if (!ids.length) return;
  const anidados = await Functions.find({ _id: { $in: ids }, kind: "role" }, { name: 1 }).lean();
  if (anidados.length) {
    throw {
      code: 400,
      title: "Rol dentro de un rol",
      detail: `Un rol no puede contener otros roles: ${anidados.map((f) => f.name).join(", ")}`,
      suggestion: "Marca funciones sencillas en vez de roles",
      error: new Error(),
    };
  }
};

// Prepara el cuerpo de un create/update: si es un rol, calcula permisos y menús desde _functions
// e ignora los que vengan en la petición (se derivan, no se asignan a mano).
self.prepare = async (payload = {}, actual = null) => {
  const kind = payload.kind || (actual && actual.kind) || "capability";
  if (kind !== "role") return payload;

  const functionIds = payload._functions || (actual && actual._functions) || [];
  await self.assertNoNestedRoles(functionIds);
  const { _permissions, _menus } = await self.composeFrom(functionIds);

  return { ...payload, kind: "role", _functions: functionIds, _permissions, _menus };
};

// Recalcula los roles que incluyan alguna de las funciones indicadas.
// Se llama tras editar una función: sin esto, los roles conservarían los permisos viejos.
self.refreshRolesContaining = async (functionId) => {
  const roles = await Functions.find({ kind: "role", _functions: functionId }, { _functions: 1 }).lean();
  for (const rol of roles) {
    const { _permissions, _menus } = await self.composeFrom(rol._functions);
    await Functions.updateOne(
      { _id: rol._id },
      { $set: { _permissions, _menus, lastUpdate: new Date().getTime() } },
    );
  }
  return roles.length;
};
