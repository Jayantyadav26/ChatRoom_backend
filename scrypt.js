import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';

/**
 * https://dev.to/advename/comment/24a9e
 */
const keyLength = 32;

/**
 * Hashes a password or a secret with a password hashing algorithm (scrypt)
 * @param {string} password
 * @returns {string} The salt+hash
 */
export const hash = async (password) => {
  return new Promise((resolve, reject) => {
    // generate random 16 bytes long salt - recommended by NodeJS Docs
    const salt = randomBytes(16).toString('hex');

    scrypt(password, salt, keyLength, (error, derivedKey) => {
      if (error) reject(error);
      // derivedKey is of type Buffer
      resolve(`${salt}.${derivedKey.toString('hex')}`);
    });
  });
};

/**
 * Compare a plain text password with a salt+hash password
 * @param {string} password The plain text password
 * @param {string} hash The hash+salt to check against
 * @returns {boolean}
 */
// export const compare = async (password, hash) => {
//   return new Promise((resolve, reject) => {
//     const [salt, hashKey] = hash.split('.');
//     // we need to pass buffer values to timingSafeEqual
//     const hashKeyBuff = Buffer.from(hashKey, 'hex');
//     scrypt(password, salt, keyLength, (error, derivedKey) => {
//       if (error) reject(error);
//       // compare the new supplied password with the hashed password using timeSafeEqual
//       resolve(timingSafeEqual(hashKeyBuff, derivedKey));
//     });
//   });
// };

// export const compare = async (password, hash) => {
//     return new Promise((resolve, reject) => {
//       const [salt, hashKey] = hash.split('.');
//       const hashKeyBuff = Buffer.from(hashKey, 'hex');
  
//       scrypt(password, salt, keyLength, (error, derivedKey) => {
//         if (error) return reject(error);
  
//         if (derivedKey.length !== hashKeyBuff.length) {
//           return resolve(false); // or reject with an error
//         }
  
//         resolve(timingSafeEqual(hashKeyBuff, derivedKey));
//       });
//     });
//   };
  

export const compare = async (password, hash) => {
    return new Promise((resolve, reject) => {
      if (!hash || typeof hash !== 'string' || !hash.includes('.')) {
        return resolve(false); // or reject with an error if preferred
      }
  
      const [salt, hashKey] = hash.split('.');
      if (!salt || !hashKey) return resolve(false); // extra safety
  
      const hashKeyBuff = Buffer.from(hashKey, 'hex');
  
      scrypt(password, salt, keyLength, (error, derivedKey) => {
        if (error) return reject(error);
  
        if (derivedKey.length !== hashKeyBuff.length) {
          return resolve(false);
        }
  
        resolve(timingSafeEqual(hashKeyBuff, derivedKey));
      });
    });
  };
  