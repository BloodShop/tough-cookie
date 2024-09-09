<!-- Do not edit this file. It is automatically generated by API Documenter. -->

[Home](./index.md) &gt; [tough-cookie](./tough-cookie.md) &gt; [Cookie](./tough-cookie.cookie.md) &gt; [toJSON](./tough-cookie.cookie.tojson.md)

## Cookie.toJSON() method

For convenience in using `JSON.stringify(cookie)`<!-- -->. Returns a plain-old Object that can be JSON-serialized.

**Signature:**

```typescript
toJSON(): SerializedCookie;
```
**Returns:**

[SerializedCookie](./tough-cookie.serializedcookie.md)

## Remarks

- Any `Date` properties (such as [Cookie.expires](./tough-cookie.cookie.expires.md)<!-- -->, [Cookie.creation](./tough-cookie.cookie.creation.md)<!-- -->, and [Cookie.lastAccessed](./tough-cookie.cookie.lastaccessed.md)<!-- -->) are exported in ISO format (`Date.toISOString()`<!-- -->).

- Custom Cookie properties are discarded. In tough-cookie 1.x, since there was no [Cookie.toJSON()](./tough-cookie.cookie.tojson.md) method explicitly defined, all enumerable properties were captured. If you want a property to be serialized, add the property name to [Cookie.serializableProperties](./tough-cookie.cookie.serializableproperties.md)<!-- -->.
