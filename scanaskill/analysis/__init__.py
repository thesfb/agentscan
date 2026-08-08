"""Analysis package: structural and language analysis for scanaskill v2.

Layers 1-4 of the v2 pipeline:
- artifact: the artifact model (SKILL.md + regions + references)
- structure: region classification (instruction/example/doc/config/script)
- instructions: instruction classifier (agent vs user-install vs doc)
- python_ast: Python AST walker for bundled scripts
- shell_parser: shell command parser with scope classification
"""
