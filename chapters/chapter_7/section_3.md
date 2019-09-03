# Parser

This section will guide you through the process of creating a parser plugin, by going through the files of `ordered-parser`, which parses an ordered list by creating macros for each item in the list.

For example:
`A) Apple B) Banana C) Cherry -> $A="Apple", $B="Banana, $C="Cherry"`

This parser supports one option, `suffix`, which lets the user choose what suffix their ordered lists use (`A) B) C)` vs. `A: B: C:`).

This parser also supports two flags, `letters` and `numbers`, which lets the user choose what symbols their ordered lists use (`A) B) C)` vs. `1) 2) 3)`).

### Example Config

```
source s_file {
  file("/tmp/input.log");
};

parser ordered {
  example_ordered_parser(flags(numbers));
};

template t_sqr {
  template("$(* $1 $1), $(* $2 $2), $(* $3 $3)\n");
};

destination d_file {
  file("/tmp/output.log" template(t_sqr));
};

log {
  source(s_file);
  parser(ordered);
  destination(d_file);
};
```

### `ordered-parser-parser.h`

```
#ifndef ORDERED_PARSER_PARSER_INCLUDED
#define ORDERED_PARSER_PARSER_INCLUDED

#include "cfg-parser.h"
#include "parser/parser-expr.h"

extern CfgParser ordered_parser_parser;

CFG_PARSER_DECLARE_LEXER_BINDING(ordered_parser_, LogParser **)

#endif
```

### `ordered-parser-parser.c`

```
#include "ordered-parser.h"
#include "cfg-parser.h"
#include "ordered-parser-grammar.h"

extern int ordered_parser_debug;

int ordered_parser_parse(CfgLexer *lexer, LogParser **instance, gpointer arg);
```

Here we have the keyword for the plugin itself, but we also add an additional keyword for the suffix option.
```
static CfgLexerKeyword ordered_parser_keywords[] =
{
  { "example_ordered_parser", KW_ORDERED_PARSER },
  { "suffix",                 KW_SUFFIX },
  { NULL }
};

CfgParser ordered_parser_parser =
{
#if SYSLOG_NG_ENABLE_DEBUG
  .debug_flag = &ordered_parser_debug,
#endif
  .name = "ordered-parser",
  .keywords = ordered_parser_keywords,
  .parse = (gint (*)(CfgLexer *, gpointer *, gpointer)) ordered_parser_parse,
  .cleanup = (void (*)(gpointer)) log_pipe_unref,
};

CFG_PARSER_IMPLEMENT_LEXER_BINDING(ordered_parser_, LogParser **)
```

### `ordered-parser-grammar.ym`

```
%code top {
#include "ordered-parser-parser.h"
}

%code {
#include "ordered-parser.h"
#include "cfg-parser.h"
#include "ordered-parser-grammar.h"
#include "syslog-names.h"
#include "messages.h"
#include "cfg-grammar.h"
}

%name-prefix "ordered_parser_"

%lex-param   {CfgLexer *lexer}
%parse-param {CfgLexer *lexer}
%parse-param {LogParser **instance}
%parse-param {gpointer arg}

/* INCLUDE_DECLS */

%token  KW_ORDERED_PARSER
%token  KW_SUFFIX

%type <ptr> parser_expr_ordered

%%

start
    : LL_CONTEXT_PARSER parser_expr_ordered { YYACCEPT; }
    ;

parser_expr_ordered
    : KW_ORDERED_PARSER '('
      {
        last_parser = *instance = ordered_parser_new(configuration);
      }
      parser_ordered_opts ')'
      {
        $$ = last_parser;
      }
    ;

parser_ordered_opts
    : parser_ordered_opt parser_ordered_opts
    |
    ;
```

Here we implement `parser_opt`, which is a standard option to include for parsers.

However, since ordered-parser supports the `suffix` option, we need to implement that too. We first make two calls to the `CHECK_ERROR` macro, to make sure the input is a valid suffix. Then we call our setter function.
```
parser_ordered_opt
    : KW_FLAGS  '(' parser_ordered_flags ')'
    | KW_SUFFX '(' string ')'
      {
        CHECK_ERROR((strlen($3)==1), @3, "Suffix must be a single character");
        CHECK_ERROR((ordered_parser_suffix_valid($3[0])), @3, "Suffix character unsupported");
        ordered_parser_set_suffix(last_parser, $3[0]);
        free($3);
      }
    | parser_opt
    ;
```

Ordered-parser also supports two flags, so we implement the flag option here by calling our flag processing function.
```
parser_ordered_flags
    : string parser_ordered_flags
      {
        CHECK_ERROR(ordered_parser_process_flag(last_parser, $1), @1, "Unknown flag"); free($1);
      }
    |
    ;

/* INCLUDE_RULES */

%%
```

### `ordered-parser.h`

```
#ifndef ORDERED_PARSER_H_INCLUDED
#define ORDERED_PARSER_H_INCLUDED

#include "parser/parser-expr.h"

typedef struct _OrderedParser
{
  LogParser super;
  gchar suffix;
  guint32 flags;
} OrderedParser;

LogParser *ordered_parser_new(GlobalConfig *cfg);
gboolean ordered_parser_process_flag(LogParser *s, const gchar *flag);
gboolean ordered_parser_suffix_valid(gchar suffix);
void ordered_parser_set_suffix(LogParser *s, gchar suffix);

#endif
```

### `ordered-parser.c`

```
#include "ordered-parser.h"
#include "scanner/kv-scanner/kv-scanner.h"

LogParser *
ordered_parser_new(GlobalConfig *cfg)
{
  OrderedParser *self = g_new0(OrderedParser, 1);

  /* Standard init method for parsers */
  log_parser_init_instance(&self->super, cfg);

  self->super.process = _process;
  self->super.super.clone = _clone;

  /* Set defaults */
  self->suffix = ')';
  self->flags = 0x0000;

  return &self->super;
}
```
The next three blocks here deal with flag handling. Note that this plugin does not actually make use of the flags; they are just here for the purpose of this guide. But our flags field is just a standard bitfield so there is nothing special about using it.

First we define constants for each flag, assigning the `letters` flag to the first bit and `numbers` the second.
```
enum
{
  OPF_LETTERS = 0x0001,
  OPF_NUMBERS = 0x0002,
};
```

We will create a `CfgFlagHandler` for each flag; this makes the process of flag handling easier. The fields for a `CfgFlagHandler` are as follows:

1. The name of the flag, which is what the user would type into their config file to use the flag.
2. The operation type, or what operation should be performed when the flag is used. This is either `CFH_SET`, which means to set (one) the bit, or `CFH_CLEAR`, which means to clear (zero) the bit.
4. The location of the `flags` field relative to the parser. This is needed because only the parser is passed into the `cfg_process_flag` function which sets/unsets the flags.
5. The constant value for the flag; the location of the bit to manipulate.
```
CfgFlagHandler ordered_parser_flag_handlers[] =
{
    { "letters", CFH_SET, offsetof(OrderedParser, flags), OPF_LETTERS},
    { "numbers", CFH_SET, offsetof(OrderedParser, flags), OPF_NUMBERS},
    { NULL },
};
```

This is the function called by from our grammar file to set the flags and we in turn call the `cfg_process_flag` to do the actual flag setting.
```
gboolean
ordered_parser_process_flag(LogParser *s, const gchar *flag)
{
  OrderedParser *self = (OrderedParser *) s;

  cfg_process_flag(ordered_parser_flag_handlers, self, flag);
}

gboolean
ordered_parser_suffix_valid(gchar suffix)
{
  return (suffix != ' '  && suffix != '\'' && suffix != '\"' );
}

void
ordered_parser_set_suffix(LogParser *s, gchar suffix)
{
  printf("SUFFIX\n");
  OrderedParser *self = (OrderedParser *) s;
  self->suffix = suffix;
}

static char *
_format_input(const gchar *input, gchar suffix)
{
  /*
   * Prepare input for scanning; specific to ordered-parser.
   * Can be ignored.
   */
}
```

The main functionality of parsers lies in their `_process` functions. It gets called when a message needs to be parsed. The function takes in a string `input`, and returns the parsed `LogMessage` through `pmsg`. To parse the input means to add the appropriate key-value pairs to the `LogMessage`; these result in macros the user can use.

To actually extract the correct keys and values from the input string, we will use a scanner (found under `lib/scanner/`). Normally we would need to write one from scratch, but since the functionality of ordered-parser is essentially a subset of the functionality of kv-parser, we will use the kv-parser's scanner, `KVScanner`.

It is important to note that parsers do not need to use scanners (for example, the date parser does not). It is just that scanners are often used. As a result of this, scanners do not *have* to be implemented in any specific way, however it would be wise to keep the standard when writing a new one.
```
static gboolean
_process(LogParser *s, LogMessage **pmsg, const LogPathOptions *path_options,
         const gchar *input, gsize input_len)
{
  OrderedParser *self = (OrderedParser *) s;

  KVScanner kv_scanner;

  /* Initialize scanner by passing in value and pair separators */
  kv_scanner_init(&kv_scanner, self->suffix, " ", FALSE);

  /* Delete spaces after suffix and pass input to KVScanner */
  gchar *formatted_input = _format_input(input, self->suffix);
  kv_scanner_input(&kv_scanner, formatted_input);

  /* Prepare to write macros to LogMessage */
  log_msg_make_writable(pmsg, path_options);
  msg_trace("ordered-parser message processing started",
            evt_tag_str ("input", input),
            evt_tag_printf("msg", "%p", *pmsg));
```

Next we have the main parsing loop. It tells the scanner to move on to the next element, and then get the key and value of that element. After, we add the key-value pair as a macro by calling the `log_msg_set_value_by_name` function.
```
  while (kv_scanner_scan_next(&kv_scanner))
    {
      const gchar *current_key = kv_scanner_get_current_key(&kv_scanner);
      const gchar *current_value = kv_scanner_get_current_value(&kv_scanner);
      log_msg_set_value_by_name(*pmsg, current_key, current_value, -1);
    }

  g_free(formatted_input);
  return TRUE;
}
```

Finally we need to implement the clone function, which is called when the same parser is used in multiple log paths.
```
static LogPipe *
_clone(LogPipe *s)
{
  OrderedParser *self = (OrderedParser *) s;

  OrderedParser *cloned;
  cloned = (OrderedParser *) ordered_parser_new(log_pipe_get_config(s));

  cloned->super = self->super;
  cloned->suffix = self->suffix;
  cloned->flags = self->flags;

  return &cloned->super.super;
}
```

### `test_ordered_parser.c`

```
#include "ordered-parser.h"
#include "apphook.h"
#include "msg_parse_lib.h"
#include "scratch-buffers.h"

#include <criterion/criterion.h>
```

This global variable is declared in order to use the same `OrderedParser` throughout each stage of the testing process (setup, unit testing, teardown).
```
LogParser *ordered_parser;
```

This function uses `ordered_parser` to parse a given ordered list; the given list is meant to represent the `${MESSAGE}` part of a syslog message. We will use this function within each unit test.
```
static LogMessage *
parse_ordered_list_into_log_message(const gchar *ordered_list)
{
  LogMessage *msg;

  /* We call this function to do the actual work */
  msg = parse_ordered_list_into_log_message_no_check(ordered_list);

  /* But in this function we make sure that parsing did not fail */
  cr_assert_not_null(msg, "expected ordered-parser success and it returned failure, ordered list=%s", ordered_list);

  return msg;
}

static LogMessage *
parse_ordered_list_into_log_message_no_check(const gchar *ordered_list)
{
  LogMessage *msg;
  LogPathOptions path_options = LOG_PATH_OPTIONS_INIT;
  LogParser *cloned_parser;

  /* First get a copy of our parser */
  cloned_parser = (LogParser *) log_pipe_clone(&ordered_parser->super);

  /* Set the ${MESSAGE} part of our dummy log message */
  msg = log_msg_new_empty();
  log_msg_set_value(msg, LM_V_MESSAGE, ordered_list, -1);

  /* Give our dummy log message to the parser for parsing */
  if (!log_parser_process_message(cloned_parser, &msg, &path_options))
    {
      /* Cleanup in case of failure */
      log_msg_unref(msg);
      log_pipe_unref(&cloned_parser->super);
      return NULL;
    }

  log_pipe_unref(&cloned_parser->super);
  return msg;
}

/* Start syslog-ng; create and initialise the global OrderedParser */
void
setup(void)
{
  app_startup();
  ordered_parser = ordered_parser_new(NULL);
  log_pipe_init((LogPipe *)ordered_parser);
}

/* Deinitialise and free the global OrderedParser; stop syslog-ng */
void
teardown(void)
{
  log_pipe_deinit((LogPipe *)ordered_parser);
  log_pipe_unref(&ordered_parser->super);
  scratch_buffers_explicit_gc();
  app_shutdown();
}
```

The general structure for our unit tests is as follows:
1. Set any ordered-parser options or flags.
2. Call the parse function we wrote above, with our `${MESSAGE}` to test.
3. Call the `libtest/` assert function to check that our message was properly parsed.
```
Test(ordered_parser, basic_default)
{
  LogMessage *msg;

  msg = parse_ordered_list_into_log_message("A) Apple");
  assert_log_message_value_by_name(msg, "A", "Apple");
  log_msg_unref(msg);
}

Test(ordered_parser, letters)
{
  LogMessage *msg;

  ordered_parser_process_flag(ordered_parser, "letters");
  msg = parse_ordered_list_into_log_message("A) Apple B) Banana C) Cherry");
  assert_log_message_value_by_name(msg, "A", "Apple");
  assert_log_message_value_by_name(msg, "B", "Banana");
  assert_log_message_value_by_name(msg, "C", "Cherry");
  log_msg_unref(msg);
}

Test(ordered_parser, numbers)
{
  LogMessage *msg;

  ordered_parser_process_flag(ordered_parser, "numbers");
  msg = parse_ordered_list_into_log_message("1) Apple 2) Banana 3) Cherry");
  assert_log_message_value_by_name(msg, "1", "Apple");
  assert_log_message_value_by_name(msg, "2", "Banana");
  assert_log_message_value_by_name(msg, "3", "Cherry");
  log_msg_unref(msg);
}

Test(ordered_parser, colon_suffix)
{
  LogMessage *msg;

  ordered_parser_set_suffix(ordered_parser, ':');
  msg = parse_ordered_list_into_log_message("A: Apple B: Banana C: Cherry");
  assert_log_message_value_by_name(msg, "A", "Apple");
  assert_log_message_value_by_name(msg, "B", "Banana");
  assert_log_message_value_by_name(msg, "C", "Cherry");
  log_msg_unref(msg);
}

Test(ordered_parser, mixed)
{
  LogMessage *msg;

  ordered_parser_process_flag(ordered_parser, "letters");
  ordered_parser_set_suffix(ordered_parser, ':');
  msg = parse_ordered_list_into_log_message("1: Apple 2: Banana 3: Cherry");
  assert_log_message_value_by_name(msg, "1", "Apple");
  assert_log_message_value_by_name(msg, "2", "Banana");
  assert_log_message_value_by_name(msg, "3", "Cherry");
  log_msg_unref(msg);
}

Test(ordered_parser, varying_spaces)
{
  LogMessage *msg;

  ordered_parser_process_flag(ordered_parser, "letters");
  ordered_parser_set_suffix(ordered_parser, '=');
  msg = parse_ordered_list_into_log_message("A=    Apple    B    =Banana C    =    Cherry");
  assert_log_message_value_by_name(msg, "A", "Apple");
  assert_log_message_value_by_name(msg, "B", "Banana");
  assert_log_message_value_by_name(msg, "C", "Cherry");
  log_msg_unref(msg);
}

TestSuite(ordered_parser, .init = setup, .fini = teardown);
```
