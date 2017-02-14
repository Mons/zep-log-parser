#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <time.h>

#include <EXTERN.h>
#include <perl.h>

#define cwarn(fmt, ...)   do{ \
	fprintf(stderr, "[WARN] %s:%d: ", __FILE__, __LINE__); \
	fprintf(stderr, fmt, ##__VA_ARGS__); \
	if (fmt[strlen(fmt) - 1] != 0x0a) { fprintf(stderr, "\n"); } \
	} while(0)

#define count(hash,id) do {\
	if ( (key = hv_fetch( (hash), (char*) &(id), 4, 0 )) && *key ) { \
		sv_setuv(*key,SvUV(*key)+1); \
	} \
	else { \
		hv_store((hash), (char*) &(id), 4, newSVuv(1), 0); \
	} \
} while(0)

#define AGENTS 8

typedef struct cnt {
	int hits;
	HV *users;
	HV *agent[AGENTS];
} cnt;


struct cnt *all = NULL;

typedef struct {
	uint32_t ts;
	uint32_t uid;
	uint32_t ua;
} rec;

static PerlInterpreter *my_perl;  /***    The Perl interpreter    ***/

int main (int argc, char **argv, char **env) {
	//PERL_SYS_INIT3(&argc,&argv,&env);
	PerlInterpreter *my_perl = perl_alloc();
	perl_construct(my_perl);

	int i,k;
	struct stat sb;
	void *addr;
	rec *r;
	rec *e;
	char fmt[1024];
	struct tm * tmp;
	
	int xxx = 0;
	
	
	SV **key;
	cnt *all_cnt;
	
	HV *stat = newHV();
	{
		SV *sv = newSV( sizeof(cnt) );
		SvUPGRADE( sv, SVt_PV );
		SvCUR_set(sv,sizeof(cnt));
		SvPOKp_on(sv);
		all_cnt = (cnt *) SvPVX( sv );
		memset(all_cnt,0,sizeof(cnt));
		for (k=0;k<AGENTS;k++) {
			all_cnt->agent[k] = newHV();
		}
		all_cnt->users = newHV();
		//cwarn("not found: %p", day_cnt);
		hv_store(stat,"total", 5,sv,0);
	}
	for (i=1; i<argc; i++) {
		cwarn("%s",argv[i]);
		int fd = open(argv[i], O_RDONLY);
		if (fd == -1) die("open %s failed: %s",argv[i],strerror(errno));
		if (fstat(fd, &sb) == -1) die("fstat %s failed: %s",argv[i],strerror(errno));
		cwarn("fd = %d, size: %zd",fd, sb.st_size);
		
		r = addr = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE,fd, 0);
		if (addr == MAP_FAILED) die("mmap failed: %s",strerror(errno));
		e = (rec *)((char *)addr + sb.st_size);
		int count = 0;
		int cur_day = 0,cur_hour = 0;
		cnt *day_cnt,*hour_cnt;
		while (r < e) {
			//cwarn("%u:%u:%u",r->ts,r->uid,r->ua);
			time_t time = r->ts;
			tmp = localtime( &time );
			int ks;
			
			strftime(fmt,1024,"%Y%m%d",tmp);
			int day_id = atoi(fmt);
			
			strftime(fmt,1024,"%Y%m%d%H",tmp);
			int hour_id = atoi(fmt);
			
			//cwarn("time = %d, day id = %d, hour id = %d (%s)",r->ts,day_id,hour_id,fmt);
			if (cur_day != day_id) {
				if (key = hv_fetch(stat, (char *)&day_id, 4, 0)) {
					day_cnt = (cnt *) SvPVX( *key );
				}
				else {
					SV *sv = newSV( sizeof(cnt) );
					SvUPGRADE( sv, SVt_PV );
					SvCUR_set(sv,sizeof(cnt));
					SvPOKp_on(sv);
					day_cnt = (cnt *) SvPVX( sv );
					memset(day_cnt,0,sizeof(cnt));
					for (k=0;k<AGENTS;k++) {
						day_cnt->agent[k] = newHV();
					}
					day_cnt->users = newHV();
					//cwarn("not found: %p", day_cnt);
					hv_store(stat,(char *)&day_id,4,sv,0);
				}
				cur_day = day_id;
			}
			if (cur_hour != hour_id) {
				//cwarn("switch hour %d -> %d",cur_hour,hour_id);
				if (key = hv_fetch(stat, (char *)&hour_id, 4, 0)) {
					hour_cnt = (cnt *) SvPVX( *key );
				}
				else {
					SV *sv = newSV( sizeof(cnt) );
					SvUPGRADE( sv, SVt_PV );
					SvCUR_set(sv,sizeof(cnt));
					SvPOKp_on(sv);
					hour_cnt = (cnt *) SvPVX( sv );
					memset(hour_cnt,0,sizeof(cnt));
					for (k=0;k<AGENTS;k++) {
						hour_cnt->agent[k] = newHV();
					}
					hour_cnt->users = newHV();
					//cwarn("not found: %p", day_cnt);
					hv_store(stat,(char *)&hour_id, 4,sv,0);
				}
				cur_hour = hour_id;
			}
			
			day_cnt->hits++;
			hour_cnt->hits++;
			//all_cnt->hits++;
			
			count(day_cnt->users, r->uid );
			count(hour_cnt->users, r->uid );
			count(all_cnt->users, r->uid );
			
			int agent = r->ua == 0xffffffff ? AGENTS-1 : r->ua;
			
			count(day_cnt->agent[agent], r->uid );
			count(hour_cnt->agent[agent], r->uid );
			count(all_cnt->agent[agent], r->uid );
			
			
			r++;
		}
		munmap(addr, sb.st_size);
		close(fd);
	}
	
	int size = HvKEYS(stat);
	AV *keys = newAV();
	HE *ent;
	char *nkey;
	STRLEN nlen;
	(void) hv_iterinit( stat );
	while ((ent = hv_iternext( stat ))) {
		char *name = HePV(ent, nlen);
		if (nlen == 4) {
			U32 id = *(uint32_t*) name;
			av_push( keys, newSVuv(id) );
		} else {
			av_push( keys, newSVpvn(name,nlen) );
		}
	}
	sortsv(AvARRAY(keys),av_len(keys)+1,Perl_sv_cmp_locale);
	printf("day/hour\tnon\tios\tand\twin\tmac\tlin\twww\tunk\thits\tusers\n");
	for (k = 0; k <= av_len(keys); k++) {
		SV **idsv = av_fetch(keys,k,0);
		U32 id = SvUV(*idsv);
		if (id > 0) {
			key = hv_fetch(stat, (char*) &id, 4 ,0);
		} else {
			key = hv_fetch(stat,SvPV_nolen(*idsv),sv_len(*idsv),0);
		}
		cnt * cn = (cnt *) SvPVX(*key);
		//cwarn("%d",SvUV(*key));
		printf("%-16s", SvPV_nolen(*idsv));
		for (i = 0; i < AGENTS; i++) {
			printf("%zu\t",HvKEYS( cn->agent[i] ));
		}
		printf("%d\t",cn->hits);
		printf("%zu\t",HvKEYS( cn->users ));
		printf("\n");
	}

}

