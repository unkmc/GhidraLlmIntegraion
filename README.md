## About
This is a [Ghidra](https://github.com/NationalSecurityAgency/ghidra) plugin that provides some functions to an [OpenAI assistant](https://platform.openai.com/docs/api-reference/assistants).

## Credit
Credit to [reverse-engineering-assistant](https://github.com/cyberkaida/reverse-engineering-assistant) for the inspiration to move from [Ghidra scripts](https://github.com/unkmc/ghidra_scripts) to a full-on [Ghidra Module](https://htmlpreview.github.io/?https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraBuild/EclipsePlugins/GhidraDev/GhidraDevPlugin/GhidraDev_README.html#NewGhidraModuleProject).

## Warning
Be careful; you can blow through a few dollars worth of OpenAI API credits pretty quickly with this.

## Current LLM Abilities
The current "tools" exposed to the LLM are [here](GhidraLlmIntegration/src/main/java/ghidrallmintegration/tools/functions).

## Example
Here's an example of renaming a function:

![Function Rename](screenshots/rename_function.png)
