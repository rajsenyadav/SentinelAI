import os

root_dir = r"c:\Users\Dell\Desktop\AI Cyber\SentinelAI"
output_file = os.path.join(root_dir, "SENTINELAI_ALL_CODE.txt")
output_file_root = r"c:\Users\Dell\Desktop\AI Cyber\SENTINELAI_ALL_CODE.txt"

extensions = ('.py', '.css', '.yaml', '.yml', 'Dockerfile')
exclude_files = ('SENTINELAI_ALL_CODE.txt', 'engineered_dataset.csv', 'events.csv', 'labels.csv', 'bundle_code.py')
exclude_dirs = ('venv', '.venv', '__pycache__', '.git', 'models', 'artifacts', 'brain')

code_blocks = []

header = """================================================================================
SentinelAI Enterprise SOC Platform — Complete Source Code Bundle
System Architect & Developer: Raj Sen (Mark 1 Systems Architect)
================================================================================

"""
code_blocks.append(header)

for dirpath, dirnames, filenames in os.walk(root_dir):
    dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
    for filename in sorted(filenames):
        if filename in exclude_files:
            continue
        if filename == 'Dockerfile' or any(filename.endswith(ext) for ext in extensions):
            full_path = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(full_path, root_dir)
            try:
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                banner = f"================================================================================\nFILE PATH: SentinelAI/{rel_path}\n================================================================================\n\n"
                code_blocks.append(banner + content + "\n\n")
            except Exception as e:
                print(f"Error reading {rel_path}: {e}")

final_text = "\n".join(code_blocks)

with open(output_file, 'w', encoding='utf-8') as f:
    f.write(final_text)

with open(output_file_root, 'w', encoding='utf-8') as f:
    f.write(final_text)

print(f"Successfully bundled {len(code_blocks)-1} source files into SENTINELAI_ALL_CODE.txt")
