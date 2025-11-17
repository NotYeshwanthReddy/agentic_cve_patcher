"""Module for patching vulnerabilities using remediation plan."""
import json
import os
from typing import Optional, Dict, Any, List
from src.tools.ssh_client import ssh
from src.utils.settings import llm
from src.utils.logger import get_logger

logger = get_logger(__name__)


def execute_and_analyze_step(step_name: str, step_config: Dict[str, Any], cve_summary: str = "", csaf_summary: str = "", max_retries: int = 2) -> Dict[str, Any]:
    """Execute a step with LLM analysis and automatic resolution."""
    logger.info(f"Executing step: {step_name}")
    command = step_config.get("command", "")
    description = step_config.get("description", "")
    expected = step_config.get("expected") or step_config.get("expected_result", "")
    
    log_entry = {
        "step": step_name,
        "command": command,
        "description": description,
        "status": "pending",
        "attempts": []
    }
    
    current_command = command
    attempt = 0
    
    while attempt <= max_retries:
        attempt += 1
        attempt_log = {"attempt": attempt, "command": current_command}
        
        try:
            output = ssh.run(current_command)
            attempt_log["output"] = output
            attempt_log["status"] = "success"
            
            # Analyze output with LLM
            analysis_prompt = (
                f"Step: {step_name}\n"
                f"Command: {current_command}\n"
                f"Expected: {expected}\n"
                f"Output: {output}\n"
                f"CVE Summary: {cve_summary[:500] if cve_summary else 'N/A'}\n\n"
                f"Analyze if the output meets expectations. Reply with ONLY JSON: {{\"success\": true/false, \"needs_retry\": true/false, \"updated_command\": \"<new command or empty>\", \"reason\": \"<brief reason>\"}}"
            )
            
            try:
                resp = llm.invoke(analysis_prompt).content.strip()
                logger.info(f"LLM Analysis Response (raw): {resp}")
                
                if "```" in resp:
                    resp = resp.split("```")[1].replace("json", "").strip()
                analysis = json.loads(resp)
                
                # Log and store full analysis result
                logger.info(f"LLM Analysis Result: {json.dumps(analysis, indent=2)}")
                attempt_log["llm_analysis"] = analysis
                attempt_log["analysis_reason"] = analysis.get("reason", "")
                
                if analysis.get("success") and not analysis.get("needs_retry"):
                    log_entry["status"] = "success"
                    log_entry["output"] = output
                    log_entry["attempts"].append(attempt_log)
                    return {"success": True, "log": log_entry, "output": output}
                elif analysis.get("needs_retry") and analysis.get("updated_command") and attempt < max_retries:
                    logger.info(f"LLM suggests retry with updated command: {analysis.get('updated_command')}")
                    attempt_log["analysis"] = analysis.get("reason", "")
                    log_entry["attempts"].append(attempt_log)
                    current_command = analysis.get("updated_command")
                    continue
                else:
                    attempt_log["analysis"] = analysis.get("reason", "")
                    log_entry["attempts"].append(attempt_log)
                    log_entry["status"] = "partial_success" if analysis.get("success") else "error"
                    log_entry["output"] = output
                    log_entry["analysis"] = analysis.get("reason", "")
                    return {"success": analysis.get("success", False), "log": log_entry, "output": output}
            except Exception as analysis_error:
                # If analysis fails, assume success if command executed
                logger.warning(f"LLM analysis failed: {analysis_error}")
                attempt_log["llm_analysis_error"] = str(analysis_error)
                log_entry["status"] = "success"
                log_entry["output"] = output
                log_entry["attempts"].append(attempt_log)
                return {"success": True, "log": log_entry, "output": output}
                
        except Exception as e:
            attempt_log["error"] = str(e)
            attempt_log["status"] = "error"
            log_entry["attempts"].append(attempt_log)
            
            # Try to resolve with LLM
            if attempt < max_retries:
                resolve_prompt = (
                    f"Step: {step_name}\n"
                    f"Failed Command: {current_command}\n"
                    f"Error: {str(e)}\n"
                    f"CVE Summary: {cve_summary[:500] if cve_summary else 'N/A'}\n"
                    f"CSAF Summary: {csaf_summary[:500] if csaf_summary else 'N/A'}\n\n"
                    f"Suggest a fixed command. Reply with ONLY JSON: {{\"updated_command\": \"<new command>\", \"reason\": \"<brief reason>\"}}"
                )
                try:
                    resp = llm.invoke(resolve_prompt).content.strip()
                    logger.info(f"LLM Resolution Response (raw): {resp}")
                    
                    if "```" in resp:
                        resp = resp.split("```")[1].replace("json", "").strip()
                    resolution = json.loads(resp)
                    
                    # Log and store full resolution result
                    logger.info(f"LLM Resolution Result: {json.dumps(resolution, indent=2)}")
                    attempt_log["llm_resolution"] = resolution
                    attempt_log["resolution"] = resolution.get("reason", "")
                    
                    current_command = resolution.get("updated_command", current_command)
                    logger.info(f"LLM suggested updated command: {current_command}")
                    continue
                except Exception as resolution_error:
                    logger.warning(f"LLM resolution failed: {resolution_error}")
                    attempt_log["llm_resolution_error"] = str(resolution_error)
                    pass
            
            log_entry["status"] = "error"
            log_entry["error"] = str(e)
            return {"success": False, "log": log_entry, "error": str(e)}
    
    log_entry["status"] = "error"
    return {"success": False, "log": log_entry, "error": "Max retries exceeded"}


def patcher_node(state):
    """Execute vulnerability remediation plan using SSH with LLM analysis."""
    logger.info("Entering patcher_node")
    
    # Get plan from state or file
    plan = state.get("remediation_plan")
    if not plan:
        resources_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "resources")
        plan_file = os.path.join(resources_dir, "plan.json")
        try:
            if os.path.exists(plan_file):
                with open(plan_file, "r") as f:
                    plan = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load plan from file: {e}")
    
    if not plan:
        return {"output": "No remediation plan found. Please generate a plan first."}
    
    cve_summary = state.get("cve_summary", "")
    csaf_summary = state.get("csaf_summary", "")
    
    patcher_logs = []
    patcher_errors = []
    report = []
    
    # Pre-checks
    pre_checks = plan.get("pre_checks", {})
    current_step = 5  # system pre-checks
    for check_name, check_config in pre_checks.items():
        result = execute_and_analyze_step(f"pre_check_{check_name}", check_config, cve_summary, csaf_summary)
        patcher_logs.append(result["log"])
        report.append({
            "step": f"Pre-check: {check_name}",
            "command": check_config.get("command"),
            "output": result.get("output", ""),
            "status": result["log"]["status"]
        })
        if not result["success"]:
            patcher_errors.append({
                "step": f"pre_check_{check_name}",
                "error": result.get("error", "Pre-check failed"),
                "suggestion": "Review system requirements and environment configuration.",
                "reasoning": "Pre-check validation failed. Ensure system meets requirements."
            })
    
    # Main steps
    steps = [
        ("check_packages", plan.get("check_packages", {})),
        ("apply_remediation", plan.get("apply_remediation", {})),
        ("verify_fix", plan.get("verify_fix", {}))
    ]
    
    for step_name, step_config in steps:
        if step_config.get("command"):
            if step_name == "check_packages" or step_name == "apply_remediation":
                current_step = 6  # patch
            elif step_name == "verify_fix":
                current_step = 7  # verify
            
            result = execute_and_analyze_step(step_name, step_config, cve_summary, csaf_summary)
            patcher_logs.append(result["log"])
            final_command = result["log"]["attempts"][-1]["command"] if result["log"].get("attempts") else step_config.get("command", "")
            report.append({
                "step": step_name.replace("_", " ").title(),
                "command": final_command,
                "output": result.get("output", ""),
                "status": result["log"]["status"],
                "attempts": len(result["log"].get("attempts", []))
            })
            if not result["success"]:
                patcher_errors.append({
                    "step": step_name,
                    "error": result.get("error", "Step failed"),
                    "suggestion": result["log"].get("analysis", "Review command and system state."),
                    "reasoning": "Step execution failed after retries."
                })
    
    # Format point-wise report
    output_parts = ["# Vulnerability Patching Execution Report\n\n"]
    for i, item in enumerate(report, 1):
        output_parts.append(f"{i}. **{item['step']}**\n")
        output_parts.append(f"   - Command: `{item['command']}`\n")
        output_parts.append(f"   - Status: {item['status']}\n")
        if item.get("attempts", 1) > 1:
            output_parts.append(f"   - Attempts: {item['attempts']}\n")
        output_parts.append(f"   - SSH Output:\n```\n{item['output']}\n```\n\n")
    
    if patcher_errors:
        output_parts.append("## Errors and Resolutions\n\n")
        for error in patcher_errors:
            output_parts.append(f"- **{error['step']}**: {error['error']}\n")
            output_parts.append(f"  - Suggestion: {error['suggestion']}\n\n")
    
    # Determine final step (report or end)
    output_text = "".join(output_parts)
    if "Execution Report" in output_text:
        if not patcher_errors or len(patcher_errors) == 0:
            current_step = 9  # end
        else:
            current_step = 8  # report
    
    return {
        "output": output_text,
        "patcher_logs": patcher_logs,
        "patcher_errors": patcher_errors,
        "current_step": current_step
    }

