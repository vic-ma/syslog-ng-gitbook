# Template Function

This section will guide you through the process of creating a template function, by going through the files of `radix-funcs`, a set of template functions that convert numbers between radixes (bases).

Template functions are represented by a `LogTemplateFunction`.

But to implement a template function, we do not work directly with a `LogTemplateFunction`. Instead, we write the necessary functions and then call one of two macro functions: `TEMPLATE_FUNCTION` or `TEMPLATE_FUNCTION_SIMPLE`. The latter is a wrapper for the former, and it is suitable for template functions that just take strings as input. `TEMPLATE_FUNCTION` is useful for template functions that need to process their inputs first.

`radix-funcs` uses `TEMPLATE_FUNCTION_SIMPLE`, and the implementation using that macro is what this guide will cover.

### Example Config
```
source s_local {
    file("/tmp/input.log");
};

destination d_local {
    file("/tmp/output.log" template("$(hex ${PID}): ${MESSAGE}\n"));
};

log {
    source(s_local);
    destination(d_local);
};
```

### `radix-funcs.h`

```
#ifndef RADIX_FUNCS_H
#define RADIX_FUNCS_H

#include "template/simple-function.h"
```

The inner workings of `TEMPLATE_FUNCTION_SIMPLE` are a bit much to go into but essentially they create a "construct" function, which is used to create a `Plugin` for the template function.  So, we need to call these macro functions, which declare the construct functions, in order to have them available to make into `Plugin` objects in the `*-plugin.c` file.
```
TEMPLATE_FUNCTION_PROTOTYPE(tf_radix_dec);
TEMPLATE_FUNCTION_PROTOTYPE(tf_radix_hex);
TEMPLATE_FUNCTION_PROTOTYPE(tf_radix_oct);

#endif
```

### `radix-funcs.c`
```
#include <math.h>

#define MAX_DIGITS 100

/* Function to check the number of arguments passed in */
static gboolean
_check_argc(gint argc, const gchar *tf_name)
{
  if (argc == 0)
    {
      return FALSE;
    }
  else if (argc > 1)
    {
      GString *error_msg = g_string_new(tf_name);
      g_string_append(error_msg, " parsing failed: too many arguments");
      msg_error(error_msg->str);
      g_string_free(error_msg, TRUE);
      return FALSE;
    }
  return TRUE;
}

/* Function to check the result of strtol for errors */
static gboolean
_check_strtol_result(gchar *endptr, const gchar *tf_name)
{
  if (*tf_name != '\0' || errno == EINVAL || errno == ERANGE)
    {
      GString *error_msg = g_string_new(tf_name);
      g_string_append(error_msg, " conversion failed: invalid number");
      msg_error(error_msg->str);
      g_string_free(error_msg, TRUE);
      return FALSE;
    }
  return TRUE;
}

/* Printf-based radix converter */
static gchar *
_convert(const char *format, long int num)
{
  return  g_strdup_printf(format, num);
}
```

For this guide we will only look at implementing the template function for decimal conversion. Implementing the others is just a matter of switching a few words and is in fact done with a macro in the actual code for this plugin.

`TEMPLATE_FUNCTION_SIMPLE` takes in one argument, which is a function with a specific prototype. So we just need to implement this function and pass it into the macro function.

We need to write a function with the following parameters:

1. The current log message being parsed, which may or may not be used depending on the template function.
2. The number of arguments passed in (not including the keyword for the template function itself).
3. The arguments passed in (not including the keyword for the template function itself).
4. The `GString` to which the result is appended.

```
static void
tf_radix_dec(LogMessage *msg, gint argc, GString *argv[], GString *result)
  {
    const gchar *tf_name = "($dec)";
    if (!_check_argc(argc, tf_name))
      return;
    long int original = strtol(argv[0]->str, NULL, 0);
    gchar *converted = _convert("%d", original);
```

At this point we have our converted integer in the form of a string and we just need to return it by appending it to `result`.
```
    g_string_append(result, converted);
    g_free(converted);
  }
```

Now we call the macro function.
```
TEMPLATE_FUNCTION_SIMPLE(tf_radix_dec);
```

### `example-plugins.c`

This is the `*-plugin.c` file for the examples module.

Using the template function macros, we don't need to modify any grammar files, but we do need to add our template functions as a `Plugin` into the plugins list. To do this we call `TEMPLATE_FUNCTION_PLUGIN`, which will make a `Plugin` based on the construct function from our `TEMPLATE_FUNCTION_SIMPLE` call, which is in turn based on our template function.
```
static Plugin example_plugins[] =
{
  /* ... */

  TEMPLATE_FUNCTION_PLUGIN(tf_radix_dec, "dec"),
  TEMPLATE_FUNCTION_PLUGIN(tf_radix_hex, "hex"),
  TEMPLATE_FUNCTION_PLUGIN(tf_radix_oct, "oct"),

  /* ... */
}
```

### `test_radix_funcs.c`

Because our template function is independent of any log message, we can just call `assert_template_format` for our tests. However, there is a variant called `assert_template_format_msg` that takes in a `LogMessage` as well, for template functions that need it. These and other template function testing functions can be found in `libtest/cr_template.c`.
```
/* ... */

Test(radix_funcs, test_radix_funcs)
{
  assert_template_format("$(dec)", "");
  assert_template_format("$(dec 10)", "10");
  assert_template_format("$(dec 0x10)", "16");
  assert_template_format("$(dec 010)", "8");

  assert_template_format("$(hex)", "");
  assert_template_format("$(hex 10)", "a");
  assert_template_format("$(hex 0x10)", "10");
  assert_template_format("$(hex 010)", "8");

  assert_template_format("$(oct)", "");
  assert_template_format("$(oct 10)", "12");
  assert_template_format("$(oct 0x10)", "20");
  assert_template_format("$(oct 010)", "10");

  assert_template_format("$(dec 2147483647)", "2147483647");
  assert_template_format("$(hex 0x7fffffff)", "0x7fffffff");
  assert_template_format("$(oct 017777777777)", "017777777777");
  assert_template_format("$(dec 2147483648)", "");
  assert_template_format("$(hex 0x80000000)", "");
  assert_template_format("$(oct 020000000000)", "");

  assert_template_format("$(dec 10a)", "");
  assert_template_format("$(hex 0x0x)", "");
  assert_template_format("$(oct 09)", "");
}

/* ... */
```