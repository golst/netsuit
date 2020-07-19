import setuptools

with open("README.md","r") as rd:
    long_description = rd.read()

setuptools.setup(
    name="netsuit",
    version="0.0.1",
    author="ray light",
    author_email="2636687065@qq.com",
    description="the good net suit",
    long_desctiption=long_description,
    long_description_content_type = "text/markdown",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python ::3",
    ],
    python_requires='>=3.6',
)