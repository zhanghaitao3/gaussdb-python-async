#!/usr/bin/env python3

import os
import sys

sys.path.insert(0, os.path.abspath('..'))

version_file = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                            'async_gaussdb', '_version.py')

with open(version_file, 'r') as f:
    for line in f:
        if line.startswith('__version__: typing.Final ='):
            _, _, version = line.partition('=')
            version = version.strip(" \n'\"")
            break
    else:
        raise RuntimeError(
            'unable to read the version from async_gaussdb/_version.py')

# -- General configuration ------------------------------------------------

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.doctest',
    'sphinx.ext.viewcode',
    'sphinx.ext.githubpages',
    'sphinx.ext.intersphinx',
]

add_module_names = False

templates_path = ['_templates']
source_suffix = '.rst'
master_doc = 'index'
project = 'async_gaussdb'
copyright = '2016-present, the asyncpg authors and contributors'
author = '<See AUTHORS file>'
release = version
language = "en"
exclude_patterns = ['_build']
pygments_style = 'sphinx'
todo_include_todos = False
suppress_warnings = ['image.nonlocal_uri']

# -- Options for HTML output ----------------------------------------------

html_theme = 'sphinx_rtd_theme'
html_title = 'async_gaussdb Documentation'
html_short_title = 'async_gaussdb'
html_static_path = ['_static']
html_sidebars = {
    '**': [
        'about.html',
        'navigation.html',
    ]
}
html_show_sourcelink = False
html_show_sphinx = False
html_show_copyright = True
htmlhelp_basename = 'async_gaussdbdoc'


# -- Options for LaTeX output ---------------------------------------------

latex_elements = {}

latex_documents = [
    (master_doc, 'async_gaussdb.tex', 'async_gaussdb Documentation',
     author, 'manual'),
]


# -- Options for manual page output ---------------------------------------

man_pages = [
    (master_doc, 'async_gaussdb', 'async_gaussdb Documentation',
     [author], 1)
]


# -- Options for Texinfo output -------------------------------------------

texinfo_documents = [
    (master_doc, 'async_gaussdb', 'async_gaussdb Documentation',
     author, 'async_gaussdb',
     'async_gaussdb is a fast GaussDB client library for the '
     'Python asyncio framework',
     'Miscellaneous'),
]

# -- Options for intersphinx ----------------------------------------------

intersphinx_mapping = {'python': ('https://docs.python.org/3', None)}
