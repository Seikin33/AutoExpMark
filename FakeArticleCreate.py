for i in range(28):
    c_file=f'./data/sample{i}-analysis-ds.md'
    expfile = f'./data/sample{i}.py'
    with open(c_file, 'r') as f:
        c_content = f.read()
    with open(expfile, 'r') as f:
        exp_content = f.read()
    with open(f'./experiments/fake/sample{i}.md', 'a') as f:
        f.write(
f'''# Decompiled Analysis
{c_content}

# Exploit
```python
{exp_content}
```
''')