#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <tr1/unordered_map>

#ifndef likely
#define likely(x) __builtin_expect((x),1)
#define unlikely(x) __builtin_expect((x),0)
#endif

extern "C" {

#include <errno.h>
#include <sys/mman.h>
#include <time.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>

typedef struct {
	uint32_t ts;
	uint32_t uid;
	uint32_t ua;
} rec;

#define cwarn(fmt, ...)   do{ \
	fprintf(stderr, "[WARN] %s:%d: ", __FILE__, __LINE__); \
	fprintf(stderr, fmt, ##__VA_ARGS__); \
	if (fmt[strlen(fmt) - 1] != 0x0a) { fprintf(stderr, "\n"); } \
	} while(0)
#define die(fmt, ...)   do{ \
	fprintf(stderr, "[WARN] %s:%d: ", __FILE__, __LINE__); \
	fprintf(stderr, fmt, ##__VA_ARGS__); \
	if (fmt[strlen(fmt) - 1] != 0x0a) { fprintf(stderr, "\n"); } \
	return(255);\
	} while(0)

}

#define AGENTS 9
#define Y2013 1356984000

typedef struct cnt {
	int hits;
	int printed;
	int merged;
	std::map <int,int> users;
	std::map <int,int> agent[AGENTS];
} cnt;

static inline void merge_cnt(cnt *dst,cnt *src) {
	int k;
	std::map<int, cnt*>::iterator it;
	std::map<int, int>::iterator ii;
	dst->hits += src->hits;
	for( ii = src->users.begin(); ii!= src->users.end(); ++ii) {
		dst->users[ (*ii).first ] += (*ii).second;
	}
	for (k=0; k < AGENTS; k++) {
		for( ii = src->agent[k].begin(); ii!= src->agent[k].end(); ++ii) {
			dst->agent[k][ (*ii).first ] += (*ii).second;
		}
	}
	src->merged = 1;
}

static inline void print_stat(cnt *c) {
	int i;
	for (i=0; i < 3; i++) {
		printf("%zd\t",c->agent[i].size());
	}
	printf("%zd\t",c->agent[7].size());
	for (i=3; i < AGENTS; i++) {
		if (i != 7) {
			printf("%zd\t",c->agent[i].size());
		}
	}
	printf("%10d",c->hits);
	printf("%10zd\t",c->users.size());
	printf("\n");
	c->printed = 1;
}

int main (int argc, char **argv) {
	static int istty = isatty(fileno(stdout));
	int i,k;
	struct stat sb;
	void * addr;
	rec *r, *e;
	struct tm *tmp, tmx;
	char fmt[1024];
	
	std::map<int, cnt*> hstat;
	std::map<int, cnt*> dstat;
	std::map<int, cnt*>::iterator itd,ith;
	std::map<int, int>::iterator ii;
	
	time_t time;
	int ua, uid;
	int cur_day = 0,cur_hour = 0;
	cnt *hc = 0,*dc = 0;
	cnt *ac = new cnt();
	
	for (i=1; i<argc; i++) {
		int fd = open(argv[i], O_RDONLY);
		if (fd == -1) die("open %s failed: %s",argv[i],strerror(errno));
		if (fstat(fd, &sb) == -1) die("fstat %s failed: %s",argv[i],strerror(errno));
		fprintf(stdout,"%s, size: %0.2fM\n",argv[i],sb.st_size/1024/1024.0);
		if (sb.st_size == 0) {
			close(fd);
			continue;
		}
		if (istty) {
			fprintf(stdout,"  0.00%%");
		}
		fflush(stdout);
		
		addr = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE,fd, 0);
		if (addr == MAP_FAILED) die("mmap failed: %s",strerror(errno));
		r = (rec *) addr;
		e = (rec *)((char *)addr + sb.st_size);
		int count = 0;
		
		while (r < e) {
			if (istty && ++count % 5000 == 0) {
				fprintf(stdout,"\r%6.2f%%",100.0 * ( (char *)r - (char*)addr) / sb.st_size);
				fflush(stdout);
				//break;
			}
			time = r->ts - Y2013;
			if (unlikely (r->ua == 0xffffffff)) {
				ua = AGENTS-1;
			}
			else if (unlikely( r->ua > AGENTS-2 )) {
				//printf("Bad agent: %d\n",r->ua);
				ua = AGENTS-1;
			}
			else {
				ua = r->ua;
			}
			uid = r->uid;
			
			int hour_id = time / 3600;
			int day_id = time / 86400;
			
			if (unlikely(cur_hour != hour_id)) {
				if (dc && hc) {
					merge_cnt(dc,hc);
				}
				if (!( hc = hstat[hour_id] ) ) hc = hstat[hour_id] = new cnt();
				cur_hour = hour_id;
			}
			if (unlikely(cur_day != day_id)) {
				if (dc) {
					merge_cnt(ac,dc);
				}
				if (!( dc = dstat[day_id] ) ) dc = dstat[day_id] = new cnt();
				cur_day = day_id;
			}
			
			hc->hits++;
			hc->users[ uid ]++;
			hc->agent[ua][ uid ]++;
			
			r++;
		}
		if (istty) { 
			fprintf(stdout,"\r%6.2f%%\n",100.0);
			fflush(stdout);
		}
		if(munmap(addr, sb.st_size) == -1) die ("munmap failed: %s", strerror(errno));
		close(fd);
		merge_cnt(dc,hc);
	}
	if (!dc->merged)
		merge_cnt(ac,dc);
	
	printf("day/hour\t\tnon\tios\tand\twm\twin\tmac\tlin\twww\tunk\t%10s%10s\n","hits","users");
	itd = dstat.begin();
	time_t dtime = (*itd).first * 86400;
	for( ith = hstat.begin(); ith!= hstat.end(); ++ith) {
		//printf("%u - %u\n", day, ( (*itd).first) );
		if ( (*ith).first / 24 > ( (*itd).first) ) {
			if ( itd != dstat.end() ) {
				time = Y2013 + (*itd).first * 86400;
				tmp = localtime_r( &time,&tmx );
				strftime(fmt,1024,"%Y-%m-%d",tmp);
				printf("%-24s", fmt);
				print_stat( (*itd).second );
				itd++;
				printf("--------------------------------------------------------------------------------------------------------------------\n");
			}
		}
		time = Y2013 + (*ith).first * 3600;
		int day = time / 86400;
		tmp = localtime_r( &time,&tmx );
		strftime(fmt,1024,"%Y-%m-%d/%H",tmp);
		printf("%-24s", fmt);
		print_stat( (*ith).second );
		
	}
	for (;itd != dstat.end(); ++itd) {
		if (!(*itd).second->printed) {
			time = Y2013 + (*itd).first * 86400;
			tmp = localtime_r( &time,&tmx );
			strftime(fmt,1024,"%Y-%m-%d",tmp);
			printf("%-24s", fmt);
			print_stat( (*itd).second );
			printf("--------------------------------------------------------------------------------------------------------------------\n");
		}
	}
	printf("%-24s", "total");
	print_stat( ac );
	
	return 0;
}