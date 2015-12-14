# Coding style for lispd

The purpose of a common coding style for a software project is first and
foremost readability and maintainability, and consistent formatting rules go a
long way in achieving that. A lot of the following document is inspired from
the Linux kernel Documentation/CodingStyle file, with most of the Spaces
section copied literally. A notable exception is the indentation style, which
is in contradiction with the original document. Thanks to the original authors
for their work!

Since LISPmob is the implementation of an IETF protocol, this document uses
the key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", and "MAY", which are to be interpreted as
described in RFC 2119.


## Indentation

The code SHOULD be indented at 4 spaces, and 8 spaces (two indentation levels)
SHOULD NOT be replaced by TAB characters. The only place for TABs is in
Makefiles. Really. Hard drive space is really cheap these days and the amount
of space saved by compacting 8 spaces into a TAB character is not worth the
potential rendering errors it may cause on different systems with different
settings.

If you use Vim or Emacs to edit existing files, the editors will be
automatically configured for the correct intendation style by the modelines at
the bottom.  Please place the contents of the modeline template file called
`modelines` from this directory at the bottom of any new source file you may
create.

The `case` labels within a `switch` statement SHOULD be aligned on the same
column:

    switch (condition) {
    case 'a':
        statement;
        break;
    case 'b':
    default:
        statement;
        break;
    }

Whitespace SHOULD NOT be left at the end of lines, nor on empty lines.


## Linebreaks

Lines are RECOMMENDED to be less than 80 character long and MUST NOT be longer
than 132 characters. When breaking long lines into several shorter ones,
syslog messages SHOULD NOT be broken, to facilitate the ability to grep for
them.


## Braces

Braces SHOULD be placed K&R style: opening brace last on the line, closing
brace first for non-function statement blocks (if, for, do, while, switch):

    if (condition) {
        statements;
    }

Function statement blocks have the opening brace first on the next line:

    int function(int x)
    {
        function body
    }

The closing brace is alone on its own line, _except_ in the cases where it is
followed by a continuation of the same statement, like:

    do {
        loop body
    } while (condition);

and

    if (condition1) {
        statements;
    } else if (condition2) {
        statements;
    } else {
        statements;
    }

Do not unnecessarily use braces where a single statement will do.

    if (condition)
        statement;

and

    if (condition)
        statement;
    else
        statement;

This does not apply if only one branch of a conditional statement is a single
statement; in the latter case use braces in both branches:

    if (condition) {
        statement;
        statement;
    } else {
        statement;
    }


## Spaces

The use of spaces depends (mostly) on function-versus-keyword usage.  Use a
space after (most) keywords.  The notable exceptions are `sizeof`, `typeof`,
`alignof`, and `__attribute__`, which look somewhat like functions (and are
usually used with parentheses in Linux, although they are not required in the
language, as in: `sizeof info` after `struct fileinfo info;` is declared).

So use a space after these keywords:

    if, switch, case, for, do, while

but not with `sizeof`, `typeof`, `alignof`, or `__attribute__`.  E.g.,

    s = sizeof(struct file);

Do not add spaces around (inside) parenthesized expressions.  This example is
_bad_:

    s = sizeof( struct file );

When declaring pointer data or a function that returns a pointer type, the
preferred use of `*` is adjacent to the data name or function name and not
adjacent to the type name.  Examples:

    char *linux_banner;
    unsigned long long memparse(char *ptr, char **retptr);
    char *match_strdup(substring_t *s);

Use one space around (on each side of) most binary and ternary operators,
such as any of these:

    =  +  -  <  >  *  /  %  |  &  ^  <=  >=  ==  !=  ?  :

but no space after unary operators:

    &  *  +  -  ~  !  sizeof  typeof  alignof  __attribute__  defined

no space before the postfix increment & decrement unary operators:

    ++  --

no space after the prefix increment & decrement unary operators:

    ++  --

and no space around the `.` and `->` structure member operators.

Do not leave trailing whitespace at the ends of lines.  Some editors with
"smart" indentation will insert whitespace at the beginning of new lines as
appropriate, so you can start typing the next line of code right away.
However, some such editors do not remove the whitespace if you end up not
putting a line of code there, such as if you leave a blank line.  As a result,
you end up with lines containing trailing whitespace.

Git will warn you about patches that introduce trailing whitespace, and can
optionally strip the trailing whitespace for you; however, if applying a series
of patches, this may make later patches in the series fail by changing their
context lines.


## Commenting

The C89 `/* ... */` style SHOULD be used for comments, and the C99-style
`//...` SHOULD NOT.

The preferred style for long (multi-line) comments is:

    /*
     * This is the preferred style for multi-line
     * comments in the LISPmob source code.
     * Please use it consistently.
     *
     * Description:  A column of asterisks on the left side,
     * with beginning and ending almost-blank lines.
     */
