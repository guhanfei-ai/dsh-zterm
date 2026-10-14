/** 保留源读取工具的纯执行契约，运行时不依赖独立 Pi Agent。 */
export interface AgentToolResult<D = Record<string, unknown>> {
  content: Array<{ type: 'text'; text: string }>
  details: D
  terminate?: boolean
}
export interface ToolDefinition {
  name: string; label: string; description: string; parameters: Record<string, unknown>
  executionMode?: string
  execute: (callId: string, params: any, signal?: AbortSignal) => Promise<AgentToolResult<any>>
}
export function defineTool<T extends ToolDefinition>(definition: T): T { return definition }
