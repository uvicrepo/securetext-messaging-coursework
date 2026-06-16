# Generic Report Template for ECE 572

**Use this template for all three assignments and modify if needed**

**This template is a starting point, not a straitjacket. If a section doesn't fit your work, adapt it; if you think it should change for everyone, open a merge request or send me an email.**
<!-- You might find it helpful to complete the assignments by following the instructions described in the local README.md file while taking notes in a seperate word processor document as 
a "rough copy" then, once you've completed the README.md instructions, use the rough copy to fill in this report as a final draft to be submitted for grading. -->

---

**Course**: ECE 572; Summer 2026
**Instructor**: Dr. Ardeshir Shojaeinasab
**Student Name**: [Your Name]  
**Student ID**: [Your Student ID]  
**Assignment**: [Assignment 1/2/3]  
**Date**: [Submission Date]  
**GitHub Repository**: [Link to **your** private repository]

---

## Executive Summary

<!-- 
Provide a brief overview of what you accomplished in this assignment. 
For Assignment 1: Focus on vulnerabilities found and security improvements made
For Assignment 2: Focus on authentication enhancements and Zero Trust implementation  
For Assignment 3: Focus on cryptographic protocols and end-to-end security
Keep this section to 1-2 paragraphs.
-->

[Write your executive summary here]

---

## Table of Contents

1. [Introduction](#introduction)
2. [Task Implementation](#task-implementation)
   - [Task X](#task-x)
   - [Task Y](#task-y)
   - [Task Z](#task-z)
3. [Security Analysis](#security-analysis)
4. [Attack Demonstrations](#attack-demonstrations)
5. [Performance Evaluation](#performance-evaluation)
6. [Lessons Learned](#lessons-learned)
7. [Conclusion](#conclusion)
8. [References](#references)

---

## 1. Introduction

### Objective
<!-- Describe the main objectives of this assignment -->

### Environment Setup
<!-- Briefly describe your development environment -->
- **Operating System**: 
- **Python Version**: 
- **Key Libraries Used**: 
- **Development Tools**: 

---

## 2. Task Overview

<!-- Replace Task X, Y, Z with actual task numbers and names 

It may be helpful to fill this out after completing each task, instead
of trying to start your work in this section.
-->

### Task X: [Task Name]

#### Objective
<!-- What was the goal of this task? -->

#### Implementation Details
<!-- Describe your implementation approach -->

#### Challenges and Solutions
<!-- What problems did you encounter and how did you solve them? -->

#### Testing and Validation
<!-- How did you test that your implementation works correctly? -->

---

### Task Y: [Task Name]

#### Implementation Details
<!-- Describe your implementation approach and include the corresponding screenshots -->

**Key Components**:
- Component 1: [Description]
- Component 2: [Description]
- Component 3: [Description]

**Code Snippet** (Key Implementation):
```python
# Include only the most important code snippets
# Do not paste entire files as the actual attack or security-fixed codes are included in the deliverables directory
def key_function():
    # Your implementation
    pass
```

#### Challenges and Solutions
<!-- What problems did you encounter and how did you solve them? -->

#### Testing and Validation
<!-- How did you test that your implementation works correctly? -->

**Test Cases**
**Evidence**:
<!-- Include extra screenshots, logs, or other evidence -->

---

### Task Z: [Task Name]

#### Implementation Details
<!-- Describe your implementation approach and include the corresponding screenshots -->

**Key Components**:
- Component 1: [Description]
- Component 2: [Description]
- Component 3: [Description]

**Code Snippet** (Key Implementation):
```python
# Include only the most important code snippets
# Do not paste entire files as the actual attack or security-fixed codes are included in the deliverables directory
def key_function():
    # Your implementation
    pass
```

#### Challenges and Solutions
<!-- What problems did you encounter and how did you solve them? -->

#### Testing and Validation
<!-- How did you test that your implementation works correctly? -->

**Test Cases**
**Evidence**:
<!-- Include extra screenshots, logs, or other evidence -->

---

## 3. Security Analysis

### Vulnerability Assessment
<!-- For Assignment 1: Document vulnerabilities found in the base application -->
<!-- For Assignment 2/3: Analyze security improvements made -->

**Identified Vulnerabilities** (Assignment 1):
| Vulnerability | Severity | Impact | Location(function/action) | Mitigation |
|---------------|----------|---------|----------|------------|
| N/A | N/A | N/A | N/A | N/A |
| N/A | N/A | N/A | N/A | N/A |
| N/A | N/A | N/A | N/A | N/A |

### Security Improvements - Before and After Comparison
<!-- Document the security enhancements you implemented -->

- **Authentication**: [If applicable otherwise remove][How it improved]
- **Authorization**: [If applicable otherwise remove][How it improved]  
- **Data Protection**: [If applicable otherwise remove][How it improved]
- **Communication Security**: [If applicable otherwise remove][How it improved]

### Threat Model
<!-- Describe the threats your implementation addresses -->

**Use the following security properties and threat actors in your threat modeling. You can add extra if needed.**

**Threat Actors Categories**:
- **Passive Network Attacker**: Can intercept but not modify traffic
- **Active Network Attacker**: Can intercept and modify traffic
- **Malicious Server Operator**: Has access to server and database
- **Compromised Client**: Attacker has access to user's device

**Security and Privacy Properties**:
- Confidentiality
- Integrity  
- Authentication
- Authorization
- Non-repudiation
- Perfect Forward Secrecy
- Privacy

---

## 4. Attack Demonstrations

### Attack 1: [Attack Name]

#### Objective
<!-- What vulnerability does this attack exploit? -->

#### Attack Setup
<!-- Describe your attack setup and tools used -->

**Tools Used**:
- Tool 1: [Purpose]
- Tool 2: [Purpose]

#### Attack Execution
<!-- Step-by-step description of the attack -->

Step 1: [Description]
Step 2: [Description]
Step 3: [Description]

#### Results and Evidence
<!-- Show evidence of successful attack, for example: -->

![Attack Screenshot](images/attack_1_evidence.png)

```
Attack Output:
[Include relevant logs or outputs]
```

#### Mitigation
<!-- How did you fix this vulnerability? -->

---

### Attack 2: [Attack Name]

#### Objective
<!-- What vulnerability does this attack exploit? -->

#### Attack Setup
<!-- Describe your attack setup and tools used -->

**Tools Used**:
- Tool 1: [Purpose]
- Tool 2: [Purpose]

#### Attack Execution
<!-- Step-by-step description of the attack -->

Step 1: [Description]
Step 2: [Description]
Step 3: [Description]

#### Results and Evidence
<!-- Show evidence of successful attack, for example: -->

![Attack Screenshot](images/attack_1_evidence.png)

```
Attack Output:
[Include relevant logs or outputs]
```

#### Mitigation
<!-- How did you fix this vulnerability? -->

---

## 5. Performance Evaluation
Basic test results in terms of resources used in terms of hardware and time. Also, if the test has limitations and fix worked properly(test passed or failed)

**Measurement Setup**:
- Test Environment: [Descriptions+Screenshots]
- Test Data: [Descriptions+Screenshots]
- Measurement Tools/Methods: [Descriptions+Screenshots]
- Test Results: [Descriptions+Screenshots]

---

## 6. Lessons Learned

### Technical Insights
<!-- What did you learn about security implementations? -->

- **Insight 1**: [Description]
- **Insight 2**: [Description]
- **Insight N**: [Description]

### Security Principles
<!-- How do your implementations relate to fundamental security principles? -->

**Applied Principles**:
- **Defense in Depth**: [How you applied this]
- **Least Privilege**: [How you applied this]
- **Fail Secure**: [How you applied this]
- **Economy of Mechanism**: [How you applied this]

---

## 7. Conclusion

### Summary of Achievements
<!-- Summarize what you accomplished -->

### Security and Privacy Posture Assessment
<!-- How secure is your final implementation? -->

**Remaining Vulnerabilities**:
- Vulnerability 1: [Description and justification]
- Vulnerability 2: [Description and justification]

**Suggest an Attack**: In two lines mention a possible existing attack to your current version in abstract
- Vulnerability 1: [Description]
- Vulnerability 2: [Description]

### Future Improvements
<!-- What would you do if you had more time? -->

**Improvement 1**: [Description]
**Improvement 2**: [Description]

---

## 8. References

<!-- 
Include all sources you referenced, including:
- Course materials and lecture notes
- RFCs and standards
- Academic papers
- Documentation and libraries used
- Tools and software references
-->

---

## Submission Checklist

Before submitting, ensure you have:

1. **Complete Report**: All sections filled out with sufficient detail
2. **Evidence**: Screenshots, logs, and demonstrations included
3. **Code**: Well-named(based on task and whether it is an attack or a fix) and well-commented and organized in your GitHub repository deliverable directory of the corresponding assignment
4. **Tests**: Security and functionality tests implemented after fix
5. **GitHub Link**: Repository link included in report and Brightspace submission
6. **Academic Integrity**: All sources properly cited, work is your own
7. **AI Disclosure**: `GENAI.md` included in deliverables, disclosing any AI use

---

**Submission Instructions**:
1. Save this report as PDF: `[StudentID]_Assignment[X]_Report.pdf`
2. Submit PDF to Brightspace
3. Include your private GitHub repository link in the Brightspace submission comments
4. Ensure your repository is private until after course completion otherwise you'll get zero grade

**Final Notes**:
- Disclose AI use in a `GENAI.md` file in your deliverables (prompts used, which files AI touched). See the Academic Integrity section of the root README.
- Be ready to explain any code you submit. If you can't explain it, don't submit it.
- Be honest about limitations and challenges
- Focus on demonstrating understanding, not just working code
- Proofread for clarity and technical accuracy

Good luck!
