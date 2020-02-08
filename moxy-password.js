"use strict";
exports.__esModule = true;
// tslint:disable-next-line: no-var-requires
var levenshtein = require('string-dist').levenshtein;
var MoxyPassword = /** @class */ (function () {
    function MoxyPassword() {
    }
    MoxyPassword.isPasswordSafe = function (password, data, patternThreshold) {
        if (patternThreshold === void 0) { patternThreshold = 0.4; }
        var _a;
        var rules = [];
        var strength = 100;
        if (password.length < 8) {
            rules.push('Password length is less than the recommended minimum of 8 characters.');
            strength -= 40;
        }
        if (password.match(/[0-9]/gi) === null) {
            rules.push('Password should contain at least one number.');
            strength -= 10;
        }
        if (password.match(/[^A-Z0-9]/gi) === null) {
            rules.push('Password should contain at least one symbol.');
            strength -= 10;
        }
        if (/[A-Z]/g.test(password) === false || /[a-z]/g.test(password) === false) {
            rules.push('Password should contain at least one upper case and one lower case letter.');
            strength -= 5;
        }
        var threshold = Math.floor(password.length * patternThreshold);
        var repeatingCharacters = password.match(/(.)\1{2,}/g);
        var repeatingCharacterLength = repeatingCharacters ? repeatingCharacters.join('').length : 0;
        if (repeatingCharacters && repeatingCharacters.join('').length > threshold) {
            rules.push('Password contains too many repeating characters and numbers.');
            strength -= 20;
        }
        var lowerPassword = password.toLowerCase();
        var sequences = [];
        var i = 0;
        var end = -1;
        var start = -1;
        var direction = -1;
        while (i < password.length) {
            if (start === -1) {
                if (lowerPassword.charCodeAt(i) === lowerPassword.charCodeAt(i + 1) - 1) {
                    start = i;
                    direction = -1;
                }
                else if (lowerPassword.charCodeAt(i) === lowerPassword.charCodeAt(i + 1) + 1) {
                    start = i;
                    direction = 1;
                }
            }
            else {
                if (direction === -1 && lowerPassword.charCodeAt(i) === lowerPassword.charCodeAt(i + 1) - 1
                    || direction === 1 && lowerPassword.charCodeAt(i) === lowerPassword.charCodeAt(i + 1) + 1) {
                    end = i + 2;
                }
                else {
                    if (start !== -1 && end !== -1) {
                        sequences.push(password.slice(start, end));
                    }
                    start = -1;
                    end = -1;
                }
            }
            i++;
        }
        var sequenceLength = sequences.length ? sequences.join('').length : 0;
        if (sequenceLength > threshold) {
            rules.push('Password contains too many characters in sequence.');
            strength -= 20;
        }
        if (data) {
            for (var _i = 0, _b = Object.keys(data); _i < _b.length; _i++) {
                var key = _b[_i];
                if (levenshtein(password, key) <= 2) {
                    rules.push('Password is too similar to a common word.');
                    strength -= 20;
                    break;
                }
                if (levenshtein(password, data[key]) <= 2) {
                    rules.push('Password is similar to data associated with your account.');
                    strength -= 20;
                    break;
                }
                else if (password.indexOf(data[key]) > -1 && password.length - data[key].length <= 6) {
                    rules.push('Password contains a word or phrase associated with your account.');
                    strength -= 10;
                }
            }
        }
        if (sequenceLength === password.length || repeatingCharacterLength === password.length) {
            strength = 0;
        }
        if (strength >= 80 && strength < 100 && password.length > 20) {
            strength = 95;
        }
        if (strength >= 80 && password.length > 30) {
            strength = 100;
        }
        var measurement = ['dangerous', 'weak', 'average', 'good', 'strong'][Math.round(strength / 25)];
        if (strength === 100 && password.length > 12) {
            measurement = 'really strong';
        }
        if (password.length > 20 && strength === 100) {
            var symbolLength = ((_a = password.match(/[^A-Z0-9]/gi)) === null || _a === void 0 ? void 0 : _a.length) || 0;
            if (symbolLength > 4) {
                measurement = 'unbreakable';
            }
        }
        return strength <= 90
            ? { measurement: measurement,
                problems: rules,
                recommendations: [
                    password.length <= 6
                        ? password + '_' + MoxyPassword.generatePassword(10 - password.length - 1)
                            + Math.floor(Math.random() * 10)
                        : MoxyPassword.generatePassword(16),
                    MoxyPassword.generatePassword(16),
                ],
                repeatingCharacters: repeatingCharacters,
                safe: false,
                sequences: sequences,
                strength: strength
            }
            : { measurement: measurement, problems: rules, repeatingCharacters: repeatingCharacters, safe: true, strength: strength, sequences: sequences };
    };
    MoxyPassword.generatePassword = function (len, charset) {
        if (len === void 0) { len = 10; }
        if (charset === void 0) { charset = '!@#%=*_-~()+^23456789abcdefghijkmnopqrstuvwxyzABCDEFGHIJKLMNPQRSTUVWXYZ'; }
        return Array.from({ length: len }, function (c) { return charset.charAt(MoxyPassword._random(0, charset.length)); })
            .join('');
    };
    MoxyPassword._random = function (min, max) {
        var distance = max - min;
        var level = Math.ceil(Math.log(distance) / Math.log(256));
        var num = parseInt(require('crypto').randomBytes(level).toString('hex'), 16);
        var result = Math.floor(num / Math.pow(256, level) * (max - min + 1) + min);
        return result;
    };
    return MoxyPassword;
}());
exports["default"] = MoxyPassword;
