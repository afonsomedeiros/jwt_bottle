import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()


setuptools.setup(
    name="JWT-Bottle",
    version="2020.07.12",
    author="Afonso Medeiros",
    author_email="afonso.b.medeiros@gmail.com",
    description="Plugin to make authentication with JWT.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/afonsomedeiros/jwt_bottle",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires=[
        'python-jose',
        'pycrypto==2.6.1'
    ]
)