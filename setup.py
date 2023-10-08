from setuptools import setup

setup(
    name="robmuxinator",
    version="0.1.0",
    author="Benjamin Maidel",
    author_email="benjamin.maidel@4am-robotics.com",
    maintainer="Philipp Gehring",
    maintainer_email="philipp.gehring@4am-robotics.com",
    description="The robmuxinator script serves as a command-line tool to manage and control tmux sessions on multiple hosts of your robot.",
    long_description=open("README.md").read(),
    url="https://github.com/mojin-robotics/robmuxinator",
    license="Apache 2.0",
    packages=["robmuxinator"],
    install_requires=[
        "argcomplete",
        "colorama",
        "paramiko",
        "pyyaml",
    ],
    entry_points={
        "console_scripts": [
            "robmuxinator = robmuxinator.robmuxinator:main",
        ]
    },
    classifiers=[
        "Intended Audience :: Developers",
        "Environment :: Console",
        "Programming Language :: Python",
    ],
)
