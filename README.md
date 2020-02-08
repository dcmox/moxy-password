# moxy-password
MoxyPassword generator and password strength test.

Password Ratings:
* dangerous (change password immediately if using)
* weak (lots of issues)
* average
* good (some password issues)
* strong
* really strong (no detected issues)
* unbreakable (likely)

## Usage
```typescript
const data = ['reddit'] // data could be previous password, demographics related to a user, etc.
const result = MoxyPassword.isPasswordSafe('reddit4life!', data)
```
Outputs:
```
{
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
}
```