import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Callable, Awaitable, List, Dict

# Logging configured by the process entrypoint (hub main.py); see base_spoke.py.
logger = logging.getLogger("WorkflowEngine")

@dataclass
class WorkflowStep:
    id: str
    description: str
    do: Callable[[Dict], Awaitable[Any]]
    undo: Callable[[Dict], Awaitable[None]]

class WorkflowContext:
    def __init__(self, tenant_id: str, resource_id: str, params: Dict[str, Any]):
        self.tenant_id = tenant_id
        self.resource_id = resource_id
        self.params = params
        self.state: Dict[str, Any] = {}

class WorkflowEngine:
    """
    Executes a sequence of workflow steps with atomic rollback on failure.
    """
    async def execute(self, workflow_id: str, steps: List[WorkflowStep], context: WorkflowContext):
        logger.info(f"Starting workflow {workflow_id} for resource {context.resource_id}")

        transaction_stack: List[WorkflowStep] = []

        try:
            for step in steps:
                logger.info(f"Executing step {step.id}: {step.description}")
                result = await step.do(context)

                # Store the step on the stack for potential rollback
                transaction_stack.append(step)

                # Update context state with step output if necessary
                if result:
                    context.state[step.id] = result

            logger.info(f"Workflow {workflow_id} completed successfully.")
            return True

        except Exception as e:
            logger.error(f"Workflow {workflow_id} failed at step {steps[len(transaction_stack)].id}: {e}")
            await self._rollback(transaction_stack, context)
            return False

    async def _rollback(self, stack: List[WorkflowStep], context: WorkflowContext):
        """
        Performs LIFO rollback of all successfully completed steps.
        """
        logger.info("Triggering atomic rollback...")
        while stack:
            step = stack.pop()
            try:
                logger.info(f"Rolling back step {step.id}: {step.description}")
                await step.undo(context)
            except Exception as e:
                logger.error(f"Critical error during rollback of step {step.id}: {e}")
                # We continue rolling back other steps even if one fails

        logger.info("Rollback complete.")

class ApprovalPolicyEngine:
    """
    Determines if a resource request is auto-approved or requires admin intervention.
    """
    def __init__(self, thresholds: Dict[str, int]):
        self.thresholds = thresholds # { "cpu": 8, "ram": 32768 }

    def evaluate(self, request_params: Dict[str, Any]) -> str:
        """
        Returns 'AUTO_APPROVED' or 'APPROVAL_REQUIRED'.
        """
        for resource, limit in self.thresholds.items():
            requested = request_params.get(resource, 0)
            if requested > limit:
                return "APPROVAL_REQUIRED"

        return "AUTO_APPROVED"
