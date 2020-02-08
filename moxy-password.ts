// tslint:disable-next-line: no-var-requires
const levenshtein = require('string-dist').levenshtein

interface IKeyValueObject {
    [key: string]: string
}

interface IMoxyPasswordResult {
    measurement: string,
    safe: boolean,
    strength: number,
    problems: string[],
    repeatingCharacters: any,
    recommendations?: string[],
    sequences: string[],
}

export default class MoxyPassword {
    public static generatePassword = (len: number = 10, charset: string = '!@#%=*_-~()+^23456789abcdefghijkmnopqrstuvwxyzABCDEFGHIJKLMNPQRSTUVWXYZ'): string => {
        return Array.from({length: len}, (c: any) => charset.charAt(Math.floor(Math.random() * charset.length)))
            .join('')
    }
    public static isPasswordSafe(password: string, data?: IKeyValueObject | string[],
                                 patternThreshold: number = 0.4): IMoxyPasswordResult {
        const rules = []
        let strength: number = 100
        if (password.length < 8) {
            rules.push('Password length is less than the recommended minimum of 8 characters.')
            strength -= 40
        }
        if (password.match(/[0-9]/gi) === null) {
            rules.push('Password should contain at least one number.')
            strength -= 10
        }
        if (password.match(/[^A-Z0-9]/gi) === null) {
            rules.push('Password should contain at least one symbol.')
            strength -= 10
        }
        if (/[A-Z]/g.test(password) === false || /[a-z]/g.test(password) === false) {
            rules.push('Password should contain at least one upper case and one lower case letter.')
            strength -= 5
        }

        const threshold = Math.floor(password.length * patternThreshold)
        const repeatingCharacters = password.match(/(.)\1{2,}/g)
        const repeatingCharacterLength = repeatingCharacters ? repeatingCharacters.join('').length : 0
        if (repeatingCharacters && repeatingCharacters.join('').length > threshold) {
            rules.push('Password contains too many repeating characters and numbers.')
            strength -= 20
        }

        const lowerPassword: string = password.toLowerCase()
        const sequences: string[] = []
        let i: number = 0
        let end: number = -1
        let start: number = -1
        let direction: number = -1
        while (i < password.length) {
            if (start === -1) {
                if (lowerPassword.charCodeAt(i) === lowerPassword.charCodeAt(i + 1) - 1) {
                    start = i
                    direction = -1
                } else if (lowerPassword.charCodeAt(i) === lowerPassword.charCodeAt(i + 1) + 1) {
                    start = i
                    direction = 1
                }
            } else {
                if (direction === -1 && lowerPassword.charCodeAt(i) === lowerPassword.charCodeAt(i + 1) - 1
                || direction === 1 && lowerPassword.charCodeAt(i) === lowerPassword.charCodeAt(i + 1) + 1) {
                    end = i + 2
                } else {
                    if (start !== -1 && end !== -1) { sequences.push(password.slice(start, end)) }
                    start = -1
                    end = -1
                }
            }
            i++
        }

        const sequenceLength = sequences.length ? sequences.join('').length : 0
        if (sequenceLength > threshold) {
            rules.push('Password contains too many characters in sequence.')
            strength -= 20
        }

        if (data) {
            for (const key of Object.keys(data)) {
                if (levenshtein(password, key) <= 2) {
                    rules.push('Password is too similar to a common word.')
                    strength -= 20
                    break
                }
                if (levenshtein(password, data[key]) <= 2) {
                    rules.push('Password is similar to data associated with your account.')
                    strength -= 20
                    break
                } else if (password.indexOf(data[key]) > -1 && password.length - data[key].length <= 6) {
                    rules.push('Password contains a word or phrase associated with your account.')
                    strength -= 10
                }
            }
        }
        if (sequenceLength === password.length || repeatingCharacterLength === password.length) {
            strength = 0
        }
        if (strength >= 80 && strength < 100 && password.length > 20) { strength = 95 }
        if (strength >= 80 && password.length > 30) { strength = 100 }
        let measurement: string = ['dangerous', 'weak', 'average', 'good', 'strong'][Math.round(strength / 25)]
        if (strength === 100 && password.length > 12) { measurement = 'really strong' }
        if (password.length > 20 && strength === 100) {
            const symbolLength = password.match(/[^A-Z0-9]/gi)?.length || 0
            if (symbolLength > 4) { measurement = 'unbreakable' }
        }
        return strength <= 90
            ? { measurement,
                problems: rules,
                recommendations: [
                    password.length <= 6
                    ? password + '_' + MoxyPassword.generatePassword(8 - password.length - 1)
                        + Math.floor(Math.random() * 10)
                    : MoxyPassword.generatePassword(10),
                    MoxyPassword.generatePassword(10),
                ],
                repeatingCharacters,
                safe: false,
                sequences,
                strength,
            }
            : { measurement, problems: rules, repeatingCharacters, safe: true, strength, sequences }
    }
}
