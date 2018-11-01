/*
 * Copyright (C) 2008, 2010 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * Author: David Zeuthen <davidz@redhat.com>
 */

#include "helper-private.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>

#include <polkit/polkit.h>

static void
send_to_helper (const gchar *str1,
                const gchar *str2)
{
  char *escaped;
  char *tmp2;
  size_t len2;

  tmp2 = g_strdup(str2);
  len2 = strlen(tmp2);
#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: writing `%s ' to stdout\n", str1);
#endif /* PAH_DEBUG */
  fprintf (stdout, "%s ", str1);

  if (len2 > 0 && tmp2[len2 - 1] == '\n')
    tmp2[len2 - 1] = '\0';
  escaped = g_strescape (tmp2, NULL);
#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: writing `%s' to stdout\n", escaped);
#endif /* PAH_DEBUG */
  fprintf (stdout, "%s", escaped);
#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: writing newline to stdout\n");
#endif /* PAH_DEBUG */
  fputc ('\n', stdout);
#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: flushing stdout\n");
#endif /* PAH_DEBUG */
  fflush (stdout);

  g_free (escaped);
  g_free (tmp2);
}

int
main (int argc, char *argv[])
{
  int rc;
  const char *user_to_auth;
  char *cookie = NULL;
  const void *authed_user;

  rc = 0;

  /* clear the entire environment to avoid attacks using with libraries honoring environment variables */
  if (_polkit_clearenv () != 0)
    goto error;

  /* set a minimal environment */
  setenv ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);

  /* check that we are setuid root */
  if (geteuid () != 0)
    {
      gchar *s;

      fprintf (stderr, "polkit-agent-helper-1: needs to be setuid root\n");

      /* Special-case a very common error triggered in jhbuild setups */
      s = g_strdup_printf ("Incorrect permissions on %s (needs to be setuid root)", argv[0]);
      send_to_helper ("PAM_ERROR_MSG", s);
      g_free (s);
      goto error;
    }

  openlog ("polkit-agent-helper-1", LOG_CONS | LOG_PID, LOG_AUTHPRIV);

  /* check for correct invocation */
  if (!(argc == 2 || argc == 3))
    {
      syslog (LOG_NOTICE, "inappropriate use of helper, wrong number of arguments [uid=%d]", getuid ());
      fprintf (stderr, "polkit-agent-helper-1: wrong number of arguments. This incident has been logged.\n");
      goto error;
    }

  user_to_auth = argv[1];

  cookie = read_cookie (argc, argv);
  if (!cookie)
    goto error;

  if (getuid () != 0)
    {
      /* check we're running with a non-tty stdin */
      if (isatty (STDIN_FILENO) != 0)
        {
          syslog (LOG_NOTICE, "inappropriate use of helper, stdin is a tty [uid=%d]", getuid ());
          fprintf (stderr, "polkit-agent-helper-1: inappropriate use of helper, stdin is a tty. This incident has been logged.\n");
          goto error;
        }
    }

#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: user to auth is '%s'.\n", user_to_auth);
#endif /* PAH_DEBUG */

  send_to_helper("PAM_PROMPT_ECHO_OFF", "Press Enter to continue:");
  if (getchar() != '\n')
    goto error;

#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: successfully authenticated user '%s'.\n", user_to_auth);
#endif /* PAH_DEBUG */

#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: sending D-Bus message to PolicyKit daemon\n");
#endif /* PAH_DEBUG */

  /* now send a D-Bus message to the PolicyKit daemon that
   * includes a) the cookie; and b) the user we authenticated
   */
  if (!send_dbus_message (cookie, user_to_auth))
    {
#ifdef PAH_DEBUG
      fprintf (stderr, "polkit-agent-helper-1: error sending D-Bus message to PolicyKit daemon\n");
#endif /* PAH_DEBUG */
      goto error;
    }

  free (cookie);

#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: successfully sent D-Bus message to PolicyKit daemon\n");
#endif /* PAH_DEBUG */

  fprintf (stdout, "SUCCESS\n");
  flush_and_wait();
  return 0;

error:
  free (cookie);
  fprintf (stdout, "FAILURE\n");
  flush_and_wait();
  return 1;
}
