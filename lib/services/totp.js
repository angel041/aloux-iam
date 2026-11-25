const { authenticator } = require("otplib");
const QRCode = require("qrcode");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const authCookie = require("../config/authCookie");
const privilegeGuard = require("../config/privilegeGuard");

authenticator.options = { window: 1 };

const self = module.exports;

// Helper

const verifyTotpToken = (secret, token) =>
  authenticator.verify({ token, secret });

// ── Códigos de respaldo: 10 de un solo uso (formato XXXX-XXXX) para entrar si se pierde la app autenticadora. Solo se
// guarda su hash; el usuario los ve una sola vez al generarlos ──
const BACKUP_CODES = 10;
const BACKUP_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // sin 0/O ni 1/I para no confundirlos al escribir
const normalizeBackup = (code) => String(code || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
const hashBackup = (code) => require("crypto").createHash("sha256").update(normalizeBackup(code)).digest("hex");

const generateBackupCodes = () => {
  const crypto = require("crypto");
  return Array.from({ length: BACKUP_CODES }, () => {
    const chars = Array.from(crypto.randomBytes(8), (byte) => BACKUP_ALPHABET[byte % BACKUP_ALPHABET.length]).join("");
    return `${chars.slice(0, 4)}-${chars.slice(4)}`;
  });
};
const backupRecords = (codes) => codes.map((code) => ({ hash: hashBackup(code), usedAt: null }));

// Un código de respaldo sin usar (8 caracteres): lo marca como usado de forma atómica y devuelve true
const consumeBackupCode = async (userId, code) => {
  if (normalizeBackup(code).length !== 8) return false;
  const result = await User.updateOne(
    { _id: userId, "data.totp.backupCodes": { $elemMatch: { hash: hashBackup(code), usedAt: null } } },
    { $set: { "data.totp.backupCodes.$.usedAt": Date.now() } },
  );
  return result.modifiedCount === 1;
};

// Código de la app (6 dígitos) o de respaldo (de un solo uso)
const verifyTotpOrBackup = async (user, secret, code) => {
  const token = String(code || "").replace(/\s/g, "");
  if (/^\d{6}$/.test(token)) return verifyTotpToken(secret, token);
  return consumeBackupCode(user._id, token);
};

const remainingBackupCodes = (user) => (user?.data?.totp?.backupCodes || []).filter((record) => !record.usedAt).length;

const verifyTempToken = (tempToken) => {
  let payload;
  try {
    payload = jwt.verify(tempToken, process.env.AUTH_SECRET);
    if (payload.type !== "totp_pending") throw new Error();
  } catch {
    throw {
      code: 401,
      title: "Sesión expirada.",
      detail: "",
      suggestion: "Vuelve a iniciar sesión",
      error: new Error(),
    };
  }
  return payload;
};

// genera QR y guarda el secreto
self.setup = async (tempToken) => {
  const payload = verifyTempToken(tempToken);

  const user = await User.findOne({ _id: payload._id });

  if (!user)
    throw {
      code: 404,
      title: "Usuario no encontrado.",
      detail: "",
      suggestion: "",
      error: new Error(),
    };

  if (!user?.data?.totp?.enabled)
    throw {
      code: 403,
      title: "2FA no habilitado.",
      detail: "",
      suggestion: "Contacta al administrador para habilitarlo",
      error: new Error(),
    };

  // Un secreto ya configurado NO se reemplaza: antes, quien tuviera la contraseña podía pedir un QR nuevo con el
  // tempToken del login, registrarlo en su propio autenticador y saltarse el 2FA por completo (además de dejar
  // fuera al dueño de la cuenta). Para reconfigurarlo, un administrador apaga y enciende el 2FA (adminToggle).
  if (user?.data?.totp?.secret)
    throw {
      code: 409,
      title: "2FA ya configurado.",
      detail: "Esta cuenta ya tiene un autenticador registrado",
      suggestion: "Si perdiste el acceso, pide a un administrador que reinicie tu 2FA",
      error: new Error(),
    };

  const secretBase32 = authenticator.generateSecret(20);
  // Sin emisor, otplib usa el correo tambien como emisor y la app de autenticacion
  // muestra "correo: correo": imposible distinguir dos cuentas del mismo usuario.
  const issuer = (process.env.PROJECT_NAME || "").trim() || "Aloux";
  const keyUri = authenticator.keyuri(user.email, issuer, secretBase32);
  const qrCode = await QRCode.toDataURL(keyUri);

  await User.updateOne(
    { _id: user._id },
    { $set: { "data.totp.secret": secretBase32 } },
  );

  return { secret: secretBase32, qrCode };
};

// valida el código tras escanear el QR
self.activate = async (tempToken, token) => {
  const payload = verifyTempToken(tempToken);

  const user = await User.findOne({ _id: payload._id });

  if (!user?.data?.totp?.secret)
    throw {
      code: 400,
      title: "QR no generado.",
      detail: "",
      suggestion: "Primero genera el QR desde /totp/setup",
      error: new Error(),
    };

  if (!verifyTotpToken(user.data.totp.secret, token))
    throw {
      code: 400,
      title: "Código inválido.",
      detail: "",
      suggestion:
        "El código ingresado es incorrecto, verifica que sea el correcto e intenta de nuevo.",
      error: new Error(),
    };

  // Deja constancia de la activación y entrega los códigos de respaldo (solo se muestran esta vez)
  const backupCodes = generateBackupCodes();
  await User.updateOne(
    { _id: user._id },
    { $set: { "data.totp.activatedAt": Date.now(), "data.totp.backupCodes": backupRecords(backupCodes) } },
  );

  return { message: "TOTP configurado correctamente", backupCodes };
};

// valida código en login y emite token real
self.checkLogin = async (token, tempToken, res, userAgent) => {
  const payload = verifyTempToken(tempToken);

  const user = await User.findOne({ _id: payload._id });

  if (!user?.data?.totp?.enabled)
    throw {
      code: 400,
      title: "2FA no está configurado.",
      detail: "",
      suggestion: "",
      error: new Error(),
    };

  if (!user?.data?.totp?.secret)
    throw {
      code: 400,
      title: "TOTP no configurado.",
      detail: "",
      suggestion: "Configura tu app Authenticator primero",
      error: new Error(),
    };

  // Código de la app o uno de respaldo (de un solo uso, si perdió la app)
  if (!(await verifyTotpOrBackup(user, user.data.totp.secret, token)))
    throw {
      code: 401,
      title: "Código inválido o expirado.",
      detail: "",
      suggestion:
        "El código ingresado es incorrecto, verifica que sea el correcto e intenta de nuevo.",
      error: new Error(),
    };

  user.data.changePwd = user?.data?.changePwd ?? false;
  user.validateKey.failedAttempts = 0;
  await user.save();

  const authToken = await user.generateAuthToken(userAgent);

  return authCookie.body(res, authToken, { changePwd: user.data.changePwd });
};

// admin habilita o deshabilita 2FA de un usuario
// req se usa para validar que el administrador pueda tocar a ese usuario (apagar el 2FA ajeno era libre)
self.adminToggle = async (userId, enabled, req) => {
  const user = await User.findOne({ _id: userId });

  if (!user)
    throw {
      code: 404,
      title: "Usuario no encontrado.",
      detail: "",
      suggestion: "",
      error: new Error(),
    };

  if (req) await privilegeGuard.assertCanManage(req, user.toObject ? user.toObject() : user);

  const update = enabled
    ? { "data.totp.enabled": true }
    : { "data.totp.enabled": false, "data.totp.secret": null, "data.totp.activatedAt": null, "data.totp.backupCodes": [] };

  await User.updateOne({ _id: user._id }, { $set: update });

  return { message: enabled ? "2FA habilitado" : "2FA deshabilitado" };
};


// ── 2FA del propio usuario (con sesión): lo activa y desactiva él mismo desde su cuenta ──
// El secreto nuevo se guarda aparte (pendingSecret) hasta que lo confirma con un código: un QR generado y no confirmado
// nunca cambia el 2FA vigente. Para desactivarlo pide un código vigente (una sesión robada no puede quitarlo)

const invalidCode = () => ({
  code: 400,
  title: "Código inválido.",
  detail: "",
  suggestion: "El código ingresado es incorrecto, verifica que sea el correcto e intenta de nuevo.",
  error: new Error(),
});

const findSelf = async (userId) => {
  const user = await User.findOne({ _id: userId }, { email: 1, data: 1 });
  if (!user)
    throw { code: 404, title: "Usuario no encontrado.", detail: "", suggestion: "", error: new Error() };
  return user;
};

const isActive = (user) => !!(user?.data?.totp?.enabled && user?.data?.totp?.secret);

self.selfStatus = async (userId) => {
  const user = await findSelf(userId);
  return { enabled: isActive(user), activatedAt: user?.data?.totp?.activatedAt || null, backupCodesLeft: isActive(user) ? remainingBackupCodes(user) : 0 };
};

self.selfSetup = async (userId) => {
  const user = await findSelf(userId);
  if (isActive(user))
    throw {
      code: 409,
      title: "2FA ya activo.",
      detail: "Tu cuenta ya tiene la verificación en dos pasos.",
      suggestion: "Desactívala primero si quieres cambiar de app autenticadora",
      error: new Error(),
    };

  const secretBase32 = authenticator.generateSecret(20);
  const issuer = (process.env.PROJECT_NAME || "").trim() || "Aloux";
  const qrCode = await QRCode.toDataURL(authenticator.keyuri(user.email, issuer, secretBase32));
  await User.updateOne({ _id: user._id }, { $set: { "data.totp.pendingSecret": secretBase32 } });

  return { secret: secretBase32, qrCode };
};

self.selfEnable = async (userId, token) => {
  const user = await findSelf(userId);
  const pending = user?.data?.totp?.pendingSecret;
  if (!pending)
    throw { code: 400, title: "QR no generado.", detail: "", suggestion: "Primero genera el QR desde /iam/totp/me/setup", error: new Error() };
  if (!verifyTotpToken(pending, String(token || "").replace(/\s/g, ""))) throw invalidCode();

  const backupCodes = generateBackupCodes();
  await User.updateOne(
    { _id: user._id },
    {
      $set: {
        "data.totp.enabled": true,
        "data.totp.secret": pending,
        "data.totp.activatedAt": Date.now(),
        "data.totp.pendingSecret": null,
        "data.totp.backupCodes": backupRecords(backupCodes),
      },
    },
  );
  // Los códigos de respaldo solo se ven en esta respuesta
  return { enabled: true, backupCodes };
};

self.selfDisable = async (userId, token) => {
  const user = await findSelf(userId);
  if (!isActive(user)) return { enabled: false };
  if (!(await verifyTotpOrBackup(user, user.data.totp.secret, token))) throw invalidCode();

  await User.updateOne(
    { _id: user._id },
    {
      $set: {
        "data.totp.enabled": false,
        "data.totp.secret": null,
        "data.totp.activatedAt": null,
        "data.totp.pendingSecret": null,
        "data.totp.backupCodes": [],
      },
    },
  );
  return { enabled: false };
};

// Códigos de respaldo nuevos (los anteriores dejan de servir); pide un código de la app vigente
self.selfRegenerateBackupCodes = async (userId, token) => {
  const user = await findSelf(userId);
  if (!isActive(user))
    throw { code: 400, title: "2FA no activo.", detail: "", suggestion: "Activa primero la verificación en dos pasos", error: new Error() };
  if (!verifyTotpToken(user.data.totp.secret, String(token || "").replace(/\s/g, ""))) throw invalidCode();

  const backupCodes = generateBackupCodes();
  await User.updateOne({ _id: user._id }, { $set: { "data.totp.backupCodes": backupRecords(backupCodes) } });
  return { backupCodes };
};

// Quita del usuario lo que nunca debe salir en una respuesta: el secreto del 2FA (con él se generan sus códigos) y los
// tokens de sesión. Se usa en /iam/auth/me y /iam/user/:USER_ID
self.redact = (user) => {
  if (!user || typeof user !== "object") return user;
  if (user.data?.totp) {
    const { secret, pendingSecret, backupCodes, ...totp } = user.data.totp;
    user.data = { ...user.data, totp };
  }
  delete user.tokens;
  return user;
};
