/* $Header:
 * https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c
 * 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -std=gnu99 -Wall -g -o mylogin login_linux.c -lcrypt */

#include <crypt.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "pwent.h"

#define LENGTH 16

int
main (int argc, char *argv[])
{
  signal (SIGINT, SIG_IGN);
  signal (SIGQUIT, SIG_IGN);
  signal (SIGTSTP, SIG_IGN);

  mypwent *passwddata;
  char user[LENGTH];
  char *user_pass;

  while (1)
    {
      printf ("login: ");
      fflush (NULL);    /* Flush all  output buffers */
      __fpurge (stdin); /* Purge any data in stdin buffer */

      if (fgets (user, LENGTH, stdin) == NULL)
        exit (0);
      user[strcspn (user, "\n")] = 0;

      user_pass = getpass ("password: ");
      passwddata = mygetpwnam (user);

      if (passwddata->pwage > 5)
        {
          printf ("Password age exceeded 5 please change your password!\n");
        }

      /* Prevention of repeated online password guesses */
      if (passwddata->pwfailed % 2 == 1)
        {
          printf ("You have to wait before trying again\n");
          sleep (passwddata->pwfailed * 20);
        }

      if (passwddata != NULL)
        {
          char *encrypted_pass = crypt (user_pass, passwddata->passwd_salt);
          if (encrypted_pass != NULL
              && strcmp (encrypted_pass, passwddata->passwd) == 0)
            {
              printf (" You're in !\n");
              /* if login is successful increment pwage */
              passwddata->pwage++;
              mysetpwent (user, passwddata);

              /* also print and reset the number of failed attempts */
              printf ("Number of failed attempts: %d\n", passwddata->pwfailed);
              passwddata->pwfailed = 0;
              mysetpwent (user, passwddata);

              /* start a shell with correct privileges */
              if (setuid (passwddata->uid) == 0)
                execve ("/bin/sh", NULL, NULL);
              else
                {
                  perror ("setuid() failed");
                  return 1;
                }
            }
          else
            {
              /* increment the number of failed attempts in the password
               * database */
              passwddata->pwfailed++;
              mysetpwent (user, passwddata);
            }
        }
      printf ("Login Incorrect \n");
    }
  return 0;
}