from distutils.core import setup, Extension

mod = Extension("jenkins", sources=["jenkins.c"])

setup(name = "Jenkins",
      version = "0.33",
      description = "Bob Jenkins's hash functions",
      ext_modules = [mod])
