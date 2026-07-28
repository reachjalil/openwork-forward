import type { LabEnvironment } from "../contracts/environment.js"
import type { McpLabStore } from "../store/contract.js"
import type { LabFaultId } from "./catalog.js"

export interface LabFaultEvaluator {
  /**
   * Returns whether the environment's active fault applies to this request.
   * Each call at a fault's application point consumes one occurrence, so the
   * once/nth triggers stay deterministic across serverless invocations.
   */
  shouldApply(faultId: LabFaultId): Promise<boolean>
  readonly activeFaultId: LabFaultId | null
}

export function createLabFaultEvaluator(store: McpLabStore, environment: LabEnvironment): LabFaultEvaluator {
  const active = environment.scenario.fault
  return {
    activeFaultId: active?.id ?? null,
    async shouldApply(faultId: LabFaultId): Promise<boolean> {
      if (!active || active.id !== faultId) return false
      const count = await store.incrementCounter(environment.id, `fault:${environment.revision}:${active.id}`)
      if (active.occurrence === "always") return true
      if (active.occurrence === "once") return count === 1
      return count === active.nth
    },
  }
}
