// DSH 0.2 的 JSON Schema 子集不接受数值/长度约束；保留本地约束并在执行前检查。
export function hostSchema(schema: any): any {
  const { minimum, maximum, minLength, maxLength, anyOf, ...rest } = schema
  const result: any = Object.fromEntries(Object.entries(rest))
  const hints = [minimum === undefined ? '' : `最小值 ${minimum}`, maximum === undefined ? '' : `最大值 ${maximum}`, minLength === undefined ? '' : `最少 ${minLength} 字符`, maxLength === undefined ? '' : `最多 ${maxLength} 字符`].filter(Boolean)
  if (hints.length) result.description = [result.description, hints.join('，')].filter(Boolean).join('；')
  if (result.properties) result.properties = Object.fromEntries(Object.entries(result.properties).map(([key, value]) => [key, hostSchema(value)]))
  if (anyOf) result.oneOf = anyOf.map(hostSchema)
  if (result.oneOf) result.oneOf = result.oneOf.map(hostSchema)
  if (result.items) result.items = hostSchema(result.items)
  return result
}
export function checkArguments(schema: any, args: any, path = '参数'): void {
  if (schema.anyOf || schema.oneOf) {
    for (const variant of schema.anyOf ?? schema.oneOf) { try { checkArguments(variant, args, path); return } catch {} }
    throw new Error(`${path}不是允许的选项`)
  }
  const mismatch = schema.type === 'object' ? !args || typeof args !== 'object' || Array.isArray(args)
    : schema.type === 'integer' ? !Number.isInteger(args) : schema.type && typeof args !== schema.type
  if (mismatch || (schema.const !== undefined && args !== schema.const) || (schema.enum && !schema.enum.includes(args))) throw new Error(`${path}类型或值无效`)
  if (typeof args === 'number' && (!Number.isFinite(args) || args < (schema.minimum ?? -Infinity) || args > (schema.maximum ?? Infinity))) throw new Error(`${path}超出范围`)
  if (typeof args === 'string' && (args.length < (schema.minLength ?? 0) || args.length > (schema.maxLength ?? Infinity))) throw new Error(`${path}长度超出范围`)
  if (schema.type === 'object') {
    for (const name of schema.required ?? []) if (!(name in args)) throw new Error(`${path}缺少 ${name}`)
    for (const [name, value] of Object.entries(args)) {
      if (schema.properties?.[name]) checkArguments(schema.properties[name], value, `${path}.${name}`)
      else if (schema.additionalProperties === false) throw new Error(`${path}包含未知字段 ${name}`)
    }
  }
}
