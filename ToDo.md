Memory to sqlite.
    - needs testing

JIRA 
    - while resolving new vulnerability in same chat, it's overwriting story details.
    - task status update (backlog, In-progress, Done)

Workflow Design: (To be decided)
    - Identify the vulnerability in the system. (using package name from Vuln_Name, and ssh commands to check if its really there.)
    - Plan Creation
    - Patching Process
    - Verification



Side problems:
    While chatting, Analyzing a vuln > creating Jira story, subtasks > analyzing another vuln (should clear the JIRA data)
    Handling JIRA sub-tasks should be smarter. (Right it's unable to identify sub-tasks by description.)

Suggestions:
    in the classify_intent, instead of having 3 different intents for JIRA, lets have only one intent and have a jira_node which redirects to the required jira node.

    Implement google search feature using the library. [pip install googlesearch-python]
