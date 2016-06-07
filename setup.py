from setuptools import setup, find_packages
import os.path as p

version = '0.0.1'

with open(p.join(p.dirname(__file__), 'requirements.txt'), 'r') as reqs:
    install_requires = [line.strip() for line in reqs]

tests_require = []


setup(
    name='bug_bounty_hunter',
    version=version,
    author='Angelis Pseftis',
    author_email='anpseftis86@gmail.com',
    url='https://github.com/anpseftis/bug_bounty_hunter',
    download_url='https://github.com/anpseftis/bug_bounty_hunter/archive/v{0}.tar.gz'.format(version),
    description='',
    long_description=open('README.rst').read(),
    keywords=[''],

    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        "Topic :: Utilities",
    ],

    install_requires=install_requires,
    tests_require=tests_require,

    packages=find_packages(exclude=['*test*']),

    entry_points={
        'console_scripts': [
            'bug_bounty_hunter = bug_bounty_hunter.bug_bounty_hunter:main'
        ],
    },
)
