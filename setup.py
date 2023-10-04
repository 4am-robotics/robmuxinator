from setuptools import setup, find_packages

setup(
    name="robmuxinator",
    version="0.1.0",
    author="Benjamin Maidel",
    author_email="benjamin.maidel@4am-robotics.com",
    description="The robmuxinator script serves as a command-line tool to manage and control tmux sessions on multiple hosts of your robot.",
    url="https://github.com/mojin-robotics/robmuxinator",
    license="Apache 2.0",
    packages=find_packages(),
    install_requires=[
        "argparse",
        "paramiko",
        "pyyaml",
        "argcomplete",
        "colorama"
    ],
    entry_points={
        "console_scripts": [
            "robmuxinator = robmuxinator:main"
        ]
    },
    classifiers=[
        'Intended Audience :: Developers',
        'Environment :: Console',
        'Programming Language :: Python',
    ]
)