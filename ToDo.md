Local CVE DB
    - create a folder with all the CVE json files
    - add a tool to fetch CVE from the local db if RHSA ID and internet access is not present (get CVE ids from additional_info state var).

JIRA 
    - reconnect to old JIRA tasks using taskID/sub-task ID.

logging
    - write logs to a file
    - log state variables, chat_history, input, output, processing steps, at every turn in the chat.

input_info
    - Add a state variable called additional_info
    - Accept the info provided by the user through chat. Utilize it during workflow generation.

Memory to sqlite.
    - needs testing in RBC Env

Workflow Design: (To be trained from SME workflow logs)
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
