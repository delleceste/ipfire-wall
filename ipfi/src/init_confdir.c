#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "includes/colors.h"
#include "includes/ipfire_userspace.h"
#include "includes/languages.h"

int setup_confdir() {
  char home[PWD_FIELDS_LEN];
  char confdirname[MAXFILENAMELEN];
  char oldconfdirname[MAXFILENAMELEN];
  DIR *home_cfgdir, *share_cfgdir, *old_cfgdir;
  uid_t euid = geteuid();

  if (euid == 0) {
    strncpy(confdirname, ROOT_CFGDIR, MAXFILENAMELEN - 1);
    confdirname[MAXFILENAMELEN - 1] = '\0';

    /* For root, we migrate from the old hidden home dir if it exists */
    get_user_info(HOMEDIR, home);
    snprintf(oldconfdirname, MAXFILENAMELEN, "%s/.IPFIRE", home);
  } else {
    get_user_info(HOMEDIR, home);
    snprintf(confdirname, MAXFILENAMELEN, "%s/.IPFIRE", home);
    snprintf(oldconfdirname, MAXFILENAMELEN, "%s/IPFIRE", home);
  }

  home_cfgdir = opendir(confdirname);
  share_cfgdir = opendir(SHARE_CFGDIR);
  old_cfgdir = opendir(oldconfdirname);

  if (share_cfgdir == NULL) {
    PRED;
    printf(TR("The default configuration directory \"%s\" does not exist!"),
           SHARE_CFGDIR);
    perror("Error: ");
    PNL;
    PVIO;
    printf(
        TR("Check your installation or try reinstalling again the firewall"));
    PNL;

    return SHARE_CFGDIR_MISSING;
  }
  if (old_cfgdir != NULL && home_cfgdir != NULL) {
    PNL;
    PNL;
    printf("----------------------------------------------------");
    PNL;
    PVIO, PUND, printf("WARNING"), PCL, PVIO, printf(":"), PNL;
    PVIO;
    printf(TR("Both configuration directories \"%s\""), oldconfdirname);
    PNL;
    PVIO;
    printf(TR("and \"%s\" exist in your home directory."), confdirname);
    PNL;
    PVIO;
    printf(TR("\"%s\" can be safely removed because the "), oldconfdirname);
    PNL;
    PVIO, printf(TR("firewall does not use it anymore"));
    PNL;
    printf("----------------------------------------------------");
    PNL;
    PNL;
    PNL;
    return CFGDIR_BOTH;
  }
  if (old_cfgdir != NULL) {
    printf(TR("Old configuration directory found: \"%s\""), oldconfdirname);
    PNL;
    printf(TR("Migrating to new configuration \"%s\"..."), confdirname);
    PTAB;
    if (rename(oldconfdirname, confdirname) < 0) {
      PRED, printf("FAILED"), PNL;
      perror("");
      return CFGDIR_MIGRATED_FAILED;
    } else {
      PGRN, printf("OK"), PNL, PNL;
      PVIO, printf(TR("Remember that if you want to explore it, "));
      PNL, PVIO, printf(TR("or change its files, you must enable "));
      PNL, PVIO, printf(TR("the \"show hidden files\" option in "));
      PNL, PVIO, printf(TR("your file browser (nautilus or konqueror "));
      PNL, PVIO, printf(TR("for instance.)"));
      PNL, PNL;
      return CFGDIR_MIGRATED;
    }
  } else if (home_cfgdir == NULL) {
    printf(TR("The directory \"%s\" does not exist."), confdirname);
    PNL;
    printf(TR("This could happen because it is the first time you run the "
              "program.."));
    PNL;
    printf(TR("Installing needed default files...\t"));
    fflush(stdout);
    if (install_default_dir(confdirname) < 0) {
      PRED, printf(TR("FAILED")), PNL, PNL;
      return CFGDIR_CREAT_FAILED;
    } else {
      PGRN, printf(TR("OK, configuration directory correctly created.")), PNL;
      if (geteuid() == 0) {
        printf(
            TR("Installing default permission rules for the administrator..."));
        fflush(stdout);
        if (install_default_admin_rules(confdirname) < 0)
          PTAB, PRED, printf(TR("FAILED"));
        else
          PTAB, PGRN,
              printf(TR("OK, correctly initialized base permission rules.")),
              PNL, PNL;
      }
      return CFGDIR_CREAT;
    }
  }

  return CFGDIR_UPTODATE;
}

int install_default_dir(const char *confdirname) {
  char copy_command[16];       /* argv [0] */
  char cp_recursive[8];        /* argv [2] */
  char source[PWD_FIELDS_LEN]; /* argv [3] */
  char *argve[1];
  int ret, status;

  // 	strncat(source, "*", 2);
  ret = fork();
  if (ret == 0) {

    strncpy(copy_command, "/bin/cp", 8);
    strncpy(cp_recursive, "-r", 3);
    strncpy(source, SHARE_CFGDIR, sizeof(source) - 1);
    source[sizeof(source) - 1] = '\0';
    //
    argve[0] = (char *)NULL;

    PNL;
    execle(copy_command, copy_command, cp_recursive, source, confdirname,
           (char *)NULL, argve);

    /* not usually reached */
    PRED, printf(TR("Error installing default configuration files"));
    perror("");
    PNL;
    exit(1);
  } else if (ret == -1) {
    perror(TR("Fork failed while installing configuration"));
    return -1;
  } else {
    /* parent */
    /* wait suspends execution of process until one of its children
     * terminates. */
    wait(&status);
  }
  if (WIFSIGNALED(status))
    printf("killed by signal %d\n", WTERMSIG(status));
  else if (WIFSTOPPED(status))
    printf("stopped by signal %d\n", WSTOPSIG(status));
  else if (WCOREDUMP(status))
    printf("core dump! Contact the author please!\n");

  /* WIFEXITED says if son exited normally (true), WEXITSTATUS
   * returns the exit status of the child, to use if WIFEXITED returned
   * true */
  if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
    return 0;
  printf("ritorno -1\n");
  return -1;
}

int install_default_admin_rules(const char *confdirname) {
  char copy_command[16]; /* argv [0] */
  char source[MAXFILENAMELEN], dest[MAXFILENAMELEN];
  char *argve[1];
  int ret, status;

  ret = fork();
  if (ret == 0) {
    strncpy(copy_command, "/bin/cp", 8);
    strncpy(source, confdirname, MAXFILENAMELEN - 1);
    source[MAXFILENAMELEN - 1] = '\0';
    strncpy(dest, confdirname, MAXFILENAMELEN - 1);
    dest[MAXFILENAMELEN - 1] = '\0';
    strncat(source, "/allowed.base", MAXFILENAMELEN - strlen(source) - 1);
    strncat(dest, "/allowed", MAXFILENAMELEN - strlen(dest) - 1);
    argve[0] = (char *)NULL;

    PNL;
    execle(copy_command, copy_command, source, dest, (char *)NULL, argve);

    /* not usually reached */
    PRED,
        printf(TR("Error installing default configuration allowed rules file"));
    perror("");
    PNL;
    exit(1);
  } else if (ret == -1) {
    perror(TR("Fork failed while installing default allowed rules"));
    return -1;
  } else {
    /* parent */
    /* wait suspends execution of process until one of its children
     * terminates. */
    wait(&status);
  }
  if (WIFSIGNALED(status))
    printf("killed by signal %d\n", WTERMSIG(status));
  else if (WIFSTOPPED(status))
    printf("stopped by signal %d\n", WSTOPSIG(status));
  else if (WCOREDUMP(status))
    printf("core dump! Contact the author please!\n");

  /* WIFEXITED says if son exited normally (true), WEXITSTATUS
   * returns the exit status of the child, to use if WIFEXITED returned
   * true */
  if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
    return 0;
  return -1;
}
