# Source Driver

This section will guide you through the process of creating a source driver plugin, by going through the files of `static-file`, a source driver that reads existing log messages from a text file.

### `static-file-parser.h`

```
#ifndef STATIC_FILE_PARSER_H
#define STATIC_FILE_PARSER_H

#include "cfg-parser.h"
#include "driver.h"

extern CfgParser static_file_parser;

CFG_PARSER_DECLARE_LEXER_BINDING(static_file_, LogDriver **)

#endif
```

### `static-file-parser.c`

We add a keyword for declaring the use of our plugin.
```
#include "driver.h"
#include "cfg-parser.h"
#include "static-file-grammar.h"

extern int static_file_debug;

int static_file_parse(CfgLexer *lexer, LogDriver **instance, gpointer arg);

static CfgLexerKeyword static_file_keywords[] =
{
  { "example_static_file", KW_STATIC_FILE },
  { NULL }
};


CfgParser static_file_parser =
{
#if ENABLE_DEBUG
  .debug_flag = &static_file_debug,
#endif
  .name = "static_file",
  .keywords = static_file_keywords,
  .parse = (gint (*)(CfgLexer *, gpointer *, gpointer)) static_file_parse,
  .cleanup = (void (*)(gpointer)) log_pipe_unref,
};

CFG_PARSER_IMPLEMENT_LEXER_BINDING(static_file_, LogDriver **)
```

### `static-file-grammar.ym`

```
%code top {
#include "static-file-parser.h"
}

%code {

#include "static-file.h"
#include "logthrsource/logthrsourcedrv.h"
#include "cfg-parser.h"
#include "static-file-grammar.h"
#include "syslog-names.h"
#include "messages.h"
#include "plugin.h"
#include "cfg-grammar.h"
#include "template/templates.h"

#include <string.h>

}

%name-prefix "static_file_"

/* Add additional parameters to the lex and parse functions */
%lex-param {CfgLexer *lexer}
%parse-param {CfgLexer *lexer}
%parse-param {LogDriver **instance}
%parse-param {gpointer arg}
```

The following line is a macro, not a comment, and must be included. It copies in the Bison declarations found in `lib/cfg-grammar.y`.
```
/* INCLUDE_DECLS */
```

Here is the token for our `"example_static_file"` keyword.
```
%token KW_STATIC_FILE
```

We declare the grammar rules as pointer types.
```
%type <ptr> source_static_file
%type <ptr> source_static_file_params

%%

start
  : LL_CONTEXT_SOURCE source_static_file  { YYACCEPT; }
  ;

source_static_file
  : KW_STATIC_FILE '(' source_static_file_params ')' { $$ = $3; }
  ;
```

`instance` is used to return the newly-created driver back to the caller. `configuration` is the `GlobalCfg` that represents the user's config file.
```
source_static_file_params
  : string
    {
      last_driver = *instance = static_file_sd_new($1, configuration);
    }
  source_static_file_options
    {
      $$ = last_driver;
      free($1);
    }
  ;

source_static_file_options
  : source_static_file_option source_static_file_options
  |
  ;
```

`threaded_source_driver_option` is a standard option for threaded source drivers.
```
source_static_file_option
  : threaded_source_driver_option
  ;
```

The following line is also a macro. It copies in the Bison rules found in `lib/cfg-grammar.y`.
```
/* INCLUDE_RULES */

%%
```

### `static-file-reader.h`

This is the header file for our file reader.
```
#ifndef STATIC_FILE_READER_H
#define STATIC_FILE_READER_H

#include <stdio.h>

#include "syslog-ng.h"

typedef struct _StaticFileReader
{
  FILE *file;
} StaticFileReader;

StaticFileReader *sfr_new(void);
gboolean sfr_open(StaticFileReader *self, gchar *pathname);
GString *sfr_nextline(StaticFileReader *self, gsize maxlen);
void sfr_close(StaticFileReader *self);
void sfr_free(StaticFileReader *self);

#endif
```

### `static-file-reader.c`

The implementation for the file reader can be ignored. It is just a simple file reader and does not interface with syslog-ng.
```
#include "static-file-reader.h"

StaticFileReader *
sfr_new(void)
{
  return g_new0(StaticFileReader, 1);
}

gboolean
sfr_open(StaticFileReader *self, gchar *pathname)
{
  self->file = fopen(pathname, "r");
  return self->file != NULL;
}

GString *
sfr_nextline(StaticFileReader *self, gsize maxlen)
{
  gchar *temp_buf = g_malloc(maxlen);
  if (!fgets(temp_buf, maxlen, self->file))
    {
      g_free(temp_buf);
      return NULL;
    }

  GString *line = g_string_new(temp_buf);
  g_free(temp_buf);
  return line;
}

void
sfr_close(StaticFileReader *self)
{
  fclose(self->file);
}

void
sfr_free(StaticFileReader *self)
{
  g_free(self);
}
```

### `static-file.h`

`static-file.c` is our main file; it implements the static-file source driver. This is its header file.

There are various ways of implementing a source driver. The one we will use is based on `LogThreadedFetcherDriver`, which has a `fetch` method that gets called automatically to get new data from the driver. It is a based on `LogThreadedSoruceDriver`, which allows for more control by giving access to `run`, which allows for control over when and how `LogMessage` are sent. This is in turn based on `LogSrcDriver`, which has a more complicated implementation process, since it takes away the abstractions that the threaded source drivers offer.

See [here](https://github.com/balabit/syslog-ng/pull/2247) for more information on threaded source drivers.
```
#ifndef STATIC_FILE_H
#define STATIC_FILE_H

#include "syslog-ng.h"
#include "driver.h"
#include "logthrsource/logthrfetcherdrv.h"
#include "static-file-reader.h"

#define SF_MAXLEN 1000

typedef struct _StaticFileSourceDriver
{
  LogThreadedFetcherDriver super;
  StaticFileReader *reader;
  gchar *pathname;
} StaticFileSourceDriver;

LogDriver *static_file_sd_new(gchar *pathname, GlobalConfig *cfg);

#endif
```

### `static-file-source.c`

For this file, we will examine the functions in the order that they are called, rather than the order that they appear in the source file.

This function is called from the grammar file. It creates and returns a new `static-file` source driver.
```
LogDriver *
static_file_sd_new(gchar *pathname, GlobalConfig *cfg)
{
  /* Allocate memory, zeroed so that we can check for uninitialized fields later on */
  StaticFileSourceDriver *self = g_new0(StaticFileSourceDriver, 1);

  /* Initialization function that fetcher drivers call */
  log_threaded_fetcher_driver_init_instance(&self->super, cfg);

  /* Override the abstract methods for LogThreadedFetcherDriver */
  self->super.connect = _open_file;
  self->super.disconnect = _close_file;
  self->super.fetch = _fetch_line;

  /* Override the abstract methods for LogPipe */
  self->super.super.super.super.super.free_fn = _free;
  self->super.super.format_stats_instance = _format_stats_instance;

  /* Set the StaticFile specific fields */
  self->reader = sfr_new();
  self->pathname = strdup(pathname);

  return &self->super.super.super.super;
}

static gboolean
_open_file(LogThreadedFetcherDriver *s)
{
  StaticFileSourceDriver *self = (StaticFileSourceDriver *) s;
  return sfr_open(self->reader, self->pathname);
}

static LogThreadedFetchResult
_fetch_line(LogThreadedFetcherDriver *s)
{
  StaticFileSourceDriver *self = (StaticFileSourceDriver *) s;

  GString *line = sfr_nextline(self->reader, SF_MAXLEN);

  if (!line)
    {
      LogThreadedFetchResult result = { THREADED_FETCH_NOT_CONNECTED, NULL };
      return result;
    }
  g_string_truncate(line, line->len-1);

  LogMessage *msg = log_msg_new_empty();
  log_msg_set_value(msg, LM_V_MESSAGE, line->str, -1);
  LogThreadedFetchResult result = { THREADED_FETCH_SUCCESS, msg };
  return result;
}

static void
_close_file(LogThreadedFetcherDriver *s)
{
  StaticFileSourceDriver *self = (StaticFileSourceDriver *) s;
  sfr_close(self->reader);
}

static void
_free(LogPipe *s)
{
  StaticFileSourceDriver *self = (StaticFileSourceDriver *) s;

  g_free(self->pathname);
  sfr_free(self->reader);

  log_threaded_fetcher_driver_free_method(s);
}


```
