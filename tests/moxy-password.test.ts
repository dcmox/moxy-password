import assert from 'assert'
import MoxyPassword from '../moxy-password'

describe('moxy-password test suite', () => {
    it('should test the strength of a password and give the proper responses', () => {
        const tests = [
            {
                data: undefined,
                password: 'aaabbbccc',
                expected: {
                    measurement: 'dangerous',
                    problems:
                    [
                        'Password should contain at least one number.',
                        'Password should contain at least one symbol.',
                        'Password should contain at least one upper case and one lower case letter.',
                        'Password contains too many repeating characters and numbers.',
                    ],
                    repeatingCharacters: [ 'aaa', 'bbb', 'ccc' ],
                    safe: false,
                    sequences: [],
                    strength: 0,
                },
            },
            {
                data: undefined,
                password: 'reddit4life',
                expected: { 
                    measurement: 'good',
                    problems: [ 
                        'Password should contain at least one symbol.',
                        'Password should contain at least one upper case and one lower case letter.',
                    ],
                    repeatingCharacters: null,
                    safe: false,
                    sequences: [],
                    strength: 85,
                },
            },
            {
                data: ['reddit'],
                password: 'reddit4life!',
                expected: {
                    measurement: 'good',
                    problems:
                    [
                        'Password should contain at least one upper case and one lower case letter.',
                        'Password contains a word or phrase associated with your account.',
                    ],
                    repeatingCharacters: null,
                    safe: false,
                    sequences: [],
                    strength: 85,
                },
            },
            {
                data: undefined,
                password: 'how4reYou?',
                expected: {
                    measurement: 'strong',
                    problems:
                    [],
                    repeatingCharacters: null,
                    safe: true,
                    sequences: [],
                    strength: 100,
                },
            },
            {
                data: undefined,
                password: '1234567',
                expected: { 
                    measurement: 'dangerous',
                    problems:
                    [
                        'Password length is less than the recommended minimum of 8 characters.',
                        'Password should contain at least one symbol.',
                        'Password should contain at least one upper case and one lower case letter.',
                        'Password contains too many characters in sequence.',
                    ],
                    repeatingCharacters: null,
                    safe: false,
                    sequences: [ '1234567' ],
                    strength: 0,
                }
            },
            {
                data: undefined,
                password: 's1Adkfj*%#qqq)$)!',
                expected: {
                    measurement: 'really strong',
                    problems: [],
                    repeatingCharacters: ['qqq'],
                    safe: true,
                    sequences: [],
                    strength: 100,
                }
            },
            {
                data: undefined,
                password: 'rjkler42234342ldfkjdf49468$**$',
                expected: {
                    measurement: 'strong',
                    problems: ['Password should contain at least one upper case and one lower case letter.'],
                    repeatingCharacters: null,
                    safe: true,
                    sequences: [ 'jkl', '234' ],
                    strength: 95,
                }
            },
            {
                data: undefined,
                password: 'Krjkler42234342ldfkjdf49468$**$',
                expected: {
                    measurement: 'really strong',
                    problems: [],
                    repeatingCharacters: null,
                    safe: true,
                    sequences: [ 'jkl', '234' ],
                    strength: 100,
                }
            },
            {
                data: undefined,
                password: 'K_rjkler42234342ldfkjdf49468$**$',
                expected: {
                    measurement: 'unbreakable',
                    problems: [],
                    repeatingCharacters: null,
                    safe: true,
                    sequences: [ 'jkl', '234' ],
                    strength: 100,
                }
            },
            {
                data: {password: 'test'},
                password: 'password12',
                expected: { 
                    measurement: 'good',
                    problems:
                    [
                        'Password should contain at least one symbol.',
                        'Password should contain at least one upper case and one lower case letter.',
                        'Password is too similar to a common word.',
                    ],
                    repeatingCharacters: null,
                    safe: false,
                    sequences: [],
                    strength: 65,
                },
            },
        ]
        tests.forEach((test) => {
            const result = MoxyPassword.isPasswordSafe(test.password, test.data)
            delete result.recommendations
            assert.deepEqual(result, test.expected)
        })
    })
})
