/**
 * AuthManager
 * 
 * Este módulo abstrae los procedimientos de inicio de sesión para cuentas Mojang y Microsoft.
 * Para cuentas Mojang no premium, genera sesiones offline sin contraseña ni APIs externas.
 * Para cuentas Mojang premium y Microsoft, usa las APIs correspondientes.
 * Los datos de las cuentas se almacenan usando ConfigManager.
 * 
 * @module authmanager
 */
// Requisitos
const ConfigManager = require('./configmanager')
const { LoggerUtil } = require('helios-core')
const { RestResponseStatus } = require('helios-core/common')
const { MicrosoftAuth, MicrosoftErrorCode } = require('helios-core/microsoft')
const { AZURE_CLIENT_ID } = require('./ipcconstants')
const Lang = require('./langloader')

const log = LoggerUtil.getLogger('AuthManager')

// Mensajes de error

function microsoftErrorDisplayable(errorCode) {
    switch (errorCode) {
        case MicrosoftErrorCode.NO_PROFILE:
            return {
                title: Lang.queryJS('auth.microsoft.error.noProfileTitle') || 'Sin Perfil',
                desc: Lang.queryJS('auth.microsoft.error.noProfileDesc') || 'No se encontró un perfil de Minecraft.'
            }
        case MicrosoftErrorCode.NO_XBOX_ACCOUNT:
            return {
                title: Lang.queryJS('auth.microsoft.error.noXboxAccountTitle') || 'Sin Cuenta Xbox',
                desc: Lang.queryJS('auth.microsoft.error.noXboxAccountDesc') || 'No se encontró una cuenta de Xbox asociada.'
            }
        case MicrosoftErrorCode.XBL_BANNED:
            return {
                title: Lang.queryJS('auth.microsoft.error.xblBannedTitle') || 'Cuenta Xbox Bloqueada',
                desc: Lang.queryJS('auth.microsoft.error.xblBannedDesc') || 'La cuenta de Xbox está bloqueada.'
            }
        case MicrosoftErrorCode.UNDER_18:
            return {
                title: Lang.queryJS('auth.microsoft.error.under18Title') || 'Menor de Edad',
                desc: Lang.queryJS('auth.microsoft.error.under18Desc') || 'La cuenta es de un menor de 18 años.'
            }
        case MicrosoftErrorCode.UNKNOWN:
            return {
                title: Lang.queryJS('auth.microsoft.error.unknownTitle') || 'Error Desconocido',
                desc: Lang.queryJS('auth.microsoft.error.unknownDesc') || 'Ocurrió un error desconocido.'
            }
    }
}

// Mensajes de error para modo offline de Mojang
function offlineErrorDisplayable(errorCode) {
    switch (errorCode) {
        case 'NOMBRE_INVALIDO':
            return {
                title: Lang.queryJS('auth.offline.error.nombreInvalidoTitle') || 'Nombre de usuario inválido',
                desc: Lang.queryJS('auth.offline.error.nombreInvalidoDesc') || 'El nombre debe tener entre 3 y 16 caracteres y contener solo letras, números o guiones bajos.'
            }
        case 'MODO_OFFLINE':
            return {
                title: Lang.queryJS('auth.offline.error.modoOfflineTitle') || 'Modo Offline',
                desc: Lang.queryJS('auth.offline.error.modoOfflineDesc') || 'Usando modo offline para cuenta no premium.'
            }
        case 'CUENTA_NO_ENCONTRADA':
            return {
                title: Lang.queryJS('auth.offline.error.cuentaNoEncontradaTitle') || 'Cuenta no encontrada',
                desc: Lang.queryJS('auth.offline.error.cuentaNoEncontradaDesc') || 'No se encontró una cuenta con ese UUID.'
            }
        default:
            return {
                title: Lang.queryJS('auth.offline.error.desconocidoTitle') || 'Error Desconocido',
                desc: Lang.queryJS('auth.offline.error.desconocidoDesc') || 'Ocurrió un error inesperado.'
            }
    }
}

// Funciones

/**
 * Añade una cuenta Mojang en modo offline para usuarios no premium.
 * Genera una sesión local sin requerir contraseña ni conexiones externas.
 * 
 * @param {string} username El nombre de usuario (3-16 caracteres, alfanumérico o guiones bajos).
 * @returns {Promise.<Object>} Promesa que resuelve con el objeto de la cuenta autenticada.
 */
exports.addMojangAccount = async function(username) {
    try {
        // Validar nombre de usuario
        if (!username || username.length < 3 || username.length > 16 || !/^[a-zA-Z0-9_]+$/.test(username)) {
            return Promise.reject(offlineErrorDisplayable('NOMBRE_INVALIDO'));
        }

        // Generar un UUID simple para modo offline
        const generateUUID = () => {
            return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
                const r = Math.random() * 16 | 0;
                const v = c === 'x' ? r : (r & 0x3 | 0x8);
                return v.toString(16);
            });
        };

        const uuid = generateUUID();
        const accessToken = `offline_${uuid}`; // Token simple para modo offline

        // Guardar la cuenta en ConfigManager
        const account = ConfigManager.addMojangAuthAccount(uuid, accessToken, username, username);
        ConfigManager.save();

        log.info(`Cuenta Mojang offline añadida para el usuario: ${username}`);
        return account;

    } catch (err) {
        log.error('Error al añadir cuenta offline:', err);
        return Promise.reject(offlineErrorDisplayable('DESCONOCIDO'));
    }
}

/**
 * Elimina una cuenta Mojang. Para cuentas offline, simplemente la elimina de la base de datos.
 * 
 * @param {string} uuid El UUID de la cuenta a eliminar.
 * @returns {Promise.<void>} Promesa que resuelve cuando la acción se completa.
 */
exports.removeMojangAccount = async function(uuid) {
    try {
        const authAcc = ConfigManager.getAuthAccount(uuid);
        if (!authAcc) {
            return Promise.reject(offlineErrorDisplayable('CUENTA_NO_ENCONTRADA'));
        }
        ConfigManager.removeAuthAccount(uuid);
        ConfigManager.save();
        log.info(`Cuenta con UUID eliminada: ${uuid}`);
        return Promise.resolve();
    } catch (err) {
        log.error('Error al eliminar cuenta:', err);
        return Promise.reject(offlineErrorDisplayable('DESCONOCIDO'));
    }
}

/**
 * Realiza el flujo completo de autenticación de Microsoft en un modo dado.
 * 
 * AUTH_MODE.FULL = Autorización completa para una nueva cuenta.
 * AUTH_MODE.MS_REFRESH = Refresco completo de autorización.
 * AUTH_MODE.MC_REFRESH = Refresco del token de MC, reutilizando el token de MS.
 * 
 * @param {string} entryCode FULL=AuthCode, MS_REFRESH=refreshToken, MC_REFRESH=accessToken
 * @param {*} authMode El modo de autenticación.
 * @returns Un objeto con todos los datos de autenticación. El objeto AccessToken será nulo cuando el modo es MC_REFRESH.
 */
const AUTH_MODE = { FULL: 0, MS_REFRESH: 1, MC_REFRESH: 2 }

async function fullMicrosoftAuthFlow(entryCode, authMode) {
    try {
        let accessTokenRaw;
        let accessToken;
        if (authMode !== AUTH_MODE.MC_REFRESH) {
            const accessTokenResponse = await MicrosoftAuth.getAccessToken(entryCode, authMode === AUTH_MODE.MS_REFRESH, AZURE_CLIENT_ID);
            if (accessTokenResponse.responseStatus === RestResponseStatus.ERROR) {
                return Promise.reject(microsoftErrorDisplayable(accessTokenResponse.microsoftErrorCode));
            }
            accessToken = accessTokenResponse.data;
            accessTokenRaw = accessToken.access_token;
        } else {
            accessTokenRaw = entryCode;
        }
        
        const xblResponse = await MicrosoftAuth.getXBLToken(accessTokenRaw);
        if (xblResponse.responseStatus === RestResponseStatus.ERROR) {
            return Promise.reject(microsoftErrorDisplayable(xblResponse.microsoftErrorCode));
        }
        const xstsResponse = await MicrosoftAuth.getXSTSToken(xblResponse.data);
        if (xstsResponse.responseStatus === RestResponseStatus.ERROR) {
            return Promise.reject(microsoftErrorDisplayable(xstsResponse.microsoftErrorCode));
        }
        const mcTokenResponse = await MicrosoftAuth.getMCAccessToken(xstsResponse.data);
        if (mcTokenResponse.responseStatus === RestResponseStatus.ERROR) {
            return Promise.reject(microsoftErrorDisplayable(mcTokenResponse.microsoftErrorCode));
        }
        const mcProfileResponse = await MicrosoftAuth.getMCProfile(mcTokenResponse.data.access_token);
        if (mcProfileResponse.responseStatus === RestResponseStatus.ERROR) {
            return Promise.reject(microsoftErrorDisplayable(mcProfileResponse.microsoftErrorCode));
        }
        return {
            accessToken,
            accessTokenRaw,
            xbl: xblResponse.data,
            xsts: xstsResponse.data,
            mcToken: mcTokenResponse.data,
            mcProfile: mcProfileResponse.data
        };
    } catch (err) {
        log.error('Error en flujo de autenticación de Microsoft:', err);
        return Promise.reject(microsoftErrorDisplayable(MicrosoftErrorCode.UNKNOWN));
    }
}

/**
 * Calcula la fecha de expiración. Avanza el tiempo de expiración 10 segundos para evitar problemas con tokens expirados.
 * 
 * @param {number} nowMs Tiempo actual en milisegundos.
 * @param {number} expiresInS Expira en (segundos).
 * @returns Fecha de expiración en milisegundos.
 */
function calculateExpiryDate(nowMs, expiresInS) {
    return nowMs + ((expiresInS - 10) * 1000);
}

/**
 * Añade una cuenta Microsoft. Pasa el código de autenticación proporcionado al flujo OAuth2.0 de Mojang.
 * Los datos resultantes se almacenan como una cuenta de autenticación en la base de datos de configuración.
 * 
 * @param {string} authCode El código de autenticación obtenido de Microsoft.
 * @returns {Promise.<Object>} Promesa que resuelve con el objeto de la cuenta autenticada.
 */
exports.addMicrosoftAccount = async function(authCode) {
    const fullAuth = await fullMicrosoftAuthFlow(authCode, AUTH_MODE.FULL);

    // Avanzar la expiración por 10 segundos para evitar problemas.
    const now = new Date().getTime();

    const ret = ConfigManager.addMicrosoftAuthAccount(
        fullAuth.mcProfile.id,
        fullAuth.mcToken.access_token,
        fullAuth.mcProfile.name,
        calculateExpiryDate(now, fullAuth.mcToken.expires_in),
        fullAuth.accessToken.access_token,
        fullAuth.accessToken.refresh_token,
        calculateExpiryDate(now, fullAuth.accessToken.expires_in)
    );
    ConfigManager.save();

    log.info(`Cuenta Microsoft añadida para el usuario: ${fullAuth.mcProfile.name}`);
    return ret;
}

/**
 * Elimina una cuenta Microsoft. Se espera que el llamador invoque el cierre de sesión OAuth a través del renderizador IPC.
 * 
 * @param {string} uuid El UUID de la cuenta a eliminar.
 * @returns {Promise.<void>} Promesa que resuelve cuando la acción se completa.
 */
exports.removeMicrosoftAccount = async function(uuid) {
    try {
        ConfigManager.removeAuthAccount(uuid);
        ConfigManager.save();
        log.info(`Cuenta Microsoft con UUID eliminada: ${uuid}`);
        return Promise.resolve();
    } catch (err) {
        log.error('Error al eliminar cuenta Microsoft:', err);
        return Promise.reject(err);
    }
}

/**
 * Valida la cuenta Mojang seleccionada. Para cuentas offline, siempre es válida si existe.
 * 
 * @returns {Promise.<boolean>} Promesa que resuelve con true para cuentas offline válidas.
 */
async function validateSelectedMojangAccount() {
    try {
        const current = ConfigManager.getSelectedAccount();
        if (!current) {
            log.error('No hay cuenta seleccionada.');
            return false;
        }
        if (current.accessToken.startsWith('offline_')) {
            log.info('Cuenta offline validada.');
            return true;
        }
        log.info('Cuenta no es offline.');
        return false;
    } catch (err) {
        log.error('Error al validar cuenta Mojang:', err);
        return false;
    }
}

/**
 * Valida la cuenta Microsoft seleccionada. Si no es válida, intenta refrescar el token de acceso.
 * Si el refresco falla, se requiere un nuevo inicio de sesión.
 * 
 * @returns {Promise.<boolean>} Promesa que resuelve con true si el token de acceso es válido, de lo contrario false.
 */
async function validateSelectedMicrosoftAccount() {
    const current = ConfigManager.getSelectedAccount();
    const now = new Date().getTime();
    const mcExpiresAt = current.expiresAt;
    const mcExpired = now >= mcExpiresAt;

    if (!mcExpired) {
        log.info('Token de Minecraft válido.');
        return true;
    }

    // El token de MC ha expirado. Verificar token de MS.
    const msExpiresAt = current.microsoft.expires_at;
    const msExpired = now >= msExpiresAt;

    if (msExpired) {
        // MS expirado, hacer refresco completo.
        try {
            const res = await fullMicrosoftAuthFlow(current.microsoft.refresh_token, AUTH_MODE.MS_REFRESH);

            ConfigManager.updateMicrosoftAuthAccount(
                current.uuid,
                res.mcToken.access_token,
                res.accessToken.access_token,
                res.accessToken.refresh_token,
                calculateExpiryDate(now, res.accessToken.expires_in),
                calculateExpiryDate(now, res.mcToken.expires_in)
            );
            ConfigManager.save();
            log.info('Cuenta Microsoft refrescada exitosamente.');
            return true;
        } catch (err) {
            log.error('Error al refrescar cuenta Microsoft:', err);
            return false;
        }
    } else {
        // Solo MC expirado, usar token MS existente.
        try {
            const res = await fullMicrosoftAuthFlow(current.microsoft.access_token, AUTH_MODE.MC_REFRESH);

            ConfigManager.updateMicrosoftAuthAccount(
                current.uuid,
                res.mcToken.access_token,
                current.microsoft.access_token,
                current.microsoft.refresh_token,
                current.microsoft.expires_at,
                calculateExpiryDate(now, res.mcToken.expires_in)
            );
            ConfigManager.save();
            log.info('Token de Minecraft refrescado exitosamente.');
            return true;
        } catch (err) {
            log.error('Error al refrescar token de Minecraft:', err);
            return false;
        }
    }
}

/**
 * Valida la cuenta de autenticación seleccionada.
 * 
 * @returns {Promise.<boolean>} Promesa que resuelve con true si el token de acceso es válido, de lo contrario false.
 */
exports.validateSelected = async function() {
    try {
        const current = ConfigManager.getSelectedAccount();
        if (!current) {
            log.error('No hay cuenta seleccionada.');
            return false;
        }

        if (current.type === 'microsoft') {
            return await validateSelectedMicrosoftAccount();
        } else {
            return await validateSelectedMojangAccount();
        }
    } catch (err) {
        log.error('Error al validar cuenta:', err);
        return false;
    }
}