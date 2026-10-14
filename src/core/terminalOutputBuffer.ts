/** 移植自 zterm 0.4.1，MIT；来源见 THIRD_PARTY_NOTICES.md。 */
/** 同时限制输出块数量与字符总量，防止长单行或大块输出绕过行数限制。 */
export class TerminalOutputBuffer {
  private chunks: Array<{ text: string; agent: boolean }> = []
  private size = 0
  private agentOutputDepth = 0
  constructor(private readonly maxChars = 1_000_000, private readonly maxChunks = 5000) {}

  push(value: string): void {
    const chunk = value.slice(-this.maxChars)
    this.chunks.push({ text: chunk, agent: this.agentOutputDepth > 0 })
    this.size += chunk.length
    while (this.chunks.length > this.maxChunks || this.size > this.maxChars) {
      const first = this.chunks[0]
      const excess = this.size - this.maxChars
      if (this.chunks.length <= this.maxChunks && excess < first.text.length) {
        first.text = first.text.slice(excess)
        this.size -= excess
      } else {
        this.size -= this.chunks.shift()!.text.length
      }
    }
  }

  /** 按宿主发送区间标记来源，不靠匹配业务文本中的协议字样删行。 */
  beginAgentOutput(): void { this.agentOutputDepth++ }
  endAgentOutput(): void { this.agentOutputDepth = Math.max(0, this.agentOutputDepth - 1) }
  recent(lines: number, includeAgent = true): string {
    return this.chunks.filter((chunk) => includeAgent || !chunk.agent).map((chunk) => chunk.text).join('')
      .split('\n').slice(-Math.min(Math.max(Math.floor(lines), 1), 5000)).join('\n')
  }
  clear(): void { this.chunks = []; this.size = 0; this.agentOutputDepth = 0 }
}
