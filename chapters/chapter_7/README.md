# Plugin Development Guide

This chapter is a guide for creating syslog-ng plugins.

## Prerequisites

### C and OOP
You should be able to program in C and be familiar with object-oriented programming.

### syslog-ng
You should understand how syslog-ng works, from a user perspective.
Recommended reading: [syslog-ng OSE Administration Guide](https://www.syslog-ng.com/technical-documents/list/syslog-ng-open-source-edition/)

### Bison
You should understand the basics of GNU Bison: how Bison is used to parse text, and the syntax of Bison grammar files.
Recommended reading: [Bison Manual](https://www.gnu.org/software/bison/manual/)

### GLib
You do not need to know anything about GLib except that syslog-ng uses it, and so you should be prepared to look up its documentation when needed. The manual is linked below, but it is probably easier to use a search engine when looking for specific docs (e.g. "Glib GString").
Recommended reading: [GLib Reference Manual](https://developer.gnome.org/glib/)

### Criterion
Syslog-ng uses the Criterion test framework, so you should know how to work with it.
Recommended reading: [Criterion Docs](https://criterion.readthedocs.io/)

### Automake/CMake
Syslog-ng supports Automake and CMake for compilation. Writing the compilation files (`Makefile.am` and `CMakeLists.txt`) is not covered in this guide.

## How this Guide Works

The first section contains information about creating modules and plugins, in general.

The following sections are guides for creating specific plugins types. Each guide goes through the files of an example plugin, explaining things on the way. Explanations will either be an in-code comment, for small but useful information, or an out-of-code text, for central information or complex information.

Each comment (in-text or out) only applies to the code that immediately follows it. So for example, the following explanation only applies to the first line of code:

---

Create a new `LogPipe` based on the user's config file.

```
LogPipe *lp = log_pipe_new(configuration);

log_pipe_unref(lp);
```
