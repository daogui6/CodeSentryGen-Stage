import os
from jinja2 import Template

def create_package_structure(package_name, version, author, license_type, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    
    readme_template = Template("# {{ package_name }}\n\nVersion: {{ version }}\nAuthor: {{ author }}\nLicense: {{ license_type }}\n")

    setup_template = Template("""from setuptools import setup, find_packages

setup(
    name='{{ package_name }}',
    version='{{ version }}',
    author='{{ author }}',
    license='{{ license_type }}',
    packages=find_packages(),
    include_package_data=True,
)
""")

    manifest_template = Template("include README.md\nrecursive-include {{ package_name }} *.py\n")

    context = {
        'package_name': package_name,
        'version': version,
        'author': author,
        'license_type': license_type
    }

    with open(os.path.join(output_dir, 'README.md'), 'w') as f:
        f.write(readme_template.render(**context))

    with open(os.path.join(output_dir, 'setup.py'), 'w') as f:
        f.write(setup_template.render(**context))

    with open(os.path.join(output_dir, 'MANIFEST.in'), 'w') as f:
        f.write(manifest_template.render(**context))

    pkg_dir = os.path.join(output_dir, package_name)
    os.makedirs(pkg_dir, exist_ok=True)
    with open(os.path.join(pkg_dir, '__init__.py'), 'w') as f:
        f.write(f'__version__ = "{version}"\n')

if __name__ == '__main__':
    create_package_structure(
        package_name='my_package',
        version='0.1.0',
        author='John Doe',
        license_type='MIT',
        output_dir='dist_package'
    )
