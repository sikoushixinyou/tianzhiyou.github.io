#include <errno.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/net.h>

#include <set>

#include "branch_pred.h"
#include "pin.H"
#include "libdft_api.h"
#include "libdft_core.h"
#include "syscall_desc.h"
#include "tagmap.h"
using namespace std;

/* default log file */
#define LOGFILE_DFL	"tool_infoLeak.log"

/* sensitive file prefix */
#define PLAINTEXT_FILE	"plaintext.txt"
#define KEY_FILE        "key.txt"

/* sensitive file tag(for different sensitive file)*/
#define	TAG_PLAINTEXT	0x01U
#define	TAG_KEY     	0x02U

char file_path[1024] = {'\0'};
/* threads context    get the vcpu's value of the thread_ctx*/
extern thread_ctx_t *threads_ctx;

/* ins descriptors */
extern ins_desc_t ins_desc[XED_ICLASS_LAST];

/* syscall descriptors */
extern syscall_desc_t syscall_desc[SYSCALL_MAX];

/* sensitive file fd set */
static std::set<int> fdset;

/* socket fd set */
static std::set<int> socketset;


/* log file path (auditing) */
static KNOB<string> logpath(KNOB_MODE_WRITEONCE, "pintool", "l", LOGFILE_DFL, "");

/* 
 * Alert Function
 *
 * @buff:	address of sensitive information buffer
 * @buffsize: buffer size
 * @tag: tag of the buffer
 */
static void alert(ADDRINT buff, size_t buffsize , tag_t tag)
{
	printf("Info Leakage Detected!\n");
	/* log file */
	FILE *logfile;

	/* auditing */
	if (likely((logfile = fopen(logpath.Value().c_str(), "a")) != NULL)) {
		/* hilarious :) */
		(void)fprintf(logfile, "****sensitive information detected!****\n");
		switch(tag)
		{
		   case TAG_PLAINTEXT:
		   
		       (void)fprintf(logfile, "plaintext leakage :");
			   break;
		   
		   case TAG_KEY:
		   
		       (void)fprintf(logfile, "key leakage :");
			   break;
		   
		   default:
		   
		       (void)fprintf(logfile, "plaintext + key leakage :");
			   break;
		   
		}
		
		(void)fprintf(logfile, "[%d]: buff:0x%08lx , buffsize:%ld\n",
							getpid(), buff, buffsize);

		(void)fprintf(logfile, "|/__\\|/__\\|/__\\|/__\\|\n");
		
		/* cleanup */
		(void)fclose(logfile);
	}
	else
		/* failed */
		LOG(string(__func__) +
			": failed while trying to open " +
			logpath.Value().c_str() + " (" +
			string(strerror(errno)) + ")\n");

	/* terminate */
	exit(EXIT_FAILURE);
}

/*
 * open(2) syscall post hook(auxiliary)
 *
 * when open(2) open the sensitive document
 * add the fd of the document to the fdset
 */
static void post_open_hook(THREADID tid, syscall_ctx_t *ctx)
{
	/* sanity check */
	if (unlikely((long)ctx->ret < 0))
		return;
	
	/* add the fd of the document to the fdset */
	//如果ctx->arg[SYSCALL_ARG0]中有"plaintext.txt"或"key.txt"
	if (strstr((char *)ctx->arg[SYSCALL_ARG0], PLAINTEXT_FILE) != NULL ||
		strstr((char *)ctx->arg[SYSCALL_ARG0], KEY_FILE) != NULL)
		//把ret插入fdset
		fdset.insert((int)ctx->ret);
}

/*
 * openat() syscall post hook(auxiliary)
 *
 * when openat() open the sensitive document
 * add the fd of the document to the fdset
 */
 //与post_open_hook基本一致，区别在于判断的是ctx->arg[SYSCALL_ARG1]
static void post_openat_hook(THREADID tid, syscall_ctx_t *ctx) 
{
  /* sanity check */
	if (unlikely((long)ctx->ret < 0))
		return;
	
	/* add the fd of the document to the fdset */
	if (strstr((char *)ctx->arg[SYSCALL_ARG1], PLAINTEXT_FILE) != NULL ||
		strstr((char *)ctx->arg[SYSCALL_ARG1], KEY_FILE) != NULL)
		fdset.insert((int)ctx->ret);
}

/*
 * socket(2) syscall post hook(auxiliary)
 *
 * when socket(2) open INET fd, add the fd to the socketset
 */
static void post_socket_hook(THREADID tid, syscall_ctx_t *ctx) 
{
  /* sanity check */
	if (unlikely((long)ctx->ret < 0))
				return;

	/* add the socket fd to the socketset */
	//其中PF_INET6=10   PF_INET=2
	if (likely(ctx->arg[SYSCALL_ARG0] == PF_INET || ctx->arg[SYSCALL_ARG0] == PF_INET6))
		socketset.insert((int)ctx->ret);
}

/*
 * accept() and accept4() syscall post hook(auxiliary)
 *
 * add the new INET fd to the socketset
 */
static void post_accept_hook(THREADID tid, syscall_ctx_t *ctx)
{
  /* sanity check */
	if (unlikely((long)ctx->ret < 0))
				return;
  /* add the socket fd to the socketset */
  //set.find()是返回给定数值的定位器
  //查找socketset里有没有ctx这个标识下的系统调用下的第一个参数
	if (likely(socketset.find(ctx->arg[SYSCALL_ARG0]) !=socketset.end()))
		socketset.insert((int)ctx->ret);//把ctx这个标识下的系统调用返回值加入socketset
}


/*
 * dup(2), dup2()syscall post hook(auxiliary)
 *
 * track copy of the fd in the fdset and socketset
 */
static void post_dup_hook(THREADID tid, syscall_ctx_t *ctx)
{
	/* not successful; optimized branch */
	if (unlikely((long)ctx->ret < 0))
		return;
	//查找fdset里有没有ctx这个标识下的系统调用下的第一个参数
	if (fdset.find((int)ctx->arg[SYSCALL_ARG0]) != fdset.end())
		fdset.insert((int)ctx->ret);
	//查找socketset里有没有ctx这个标识下的系统调用下的第一个参数
	else if(socketset.find((int)ctx->arg[SYSCALL_ARG0]) != socketset.end())
	    socketset.insert((int)ctx->ret);
	else
	    return;
}


/*
 * close(2)syscall post hook(auxiliary)
 *
 * remove fd in the fdset and socketset
 */
static void post_close_hook(THREADID tid, syscall_ctx_t *ctx)
{
	/* iterator */
	std::set<int>::iterator it_f;
	std::set<int>::iterator it_s;

	/* not successful; optimized branch */
	if (unlikely((long)ctx->ret < 0))
		return;
	//查找fdset和socketset里有没有ctx这个标识下的系统调用下的第一个参数
	//如果有的话把它删除
	it_f = fdset.find((int)ctx->arg[SYSCALL_ARG0]);
	it_s = socketset.find((int)ctx->arg[SYSCALL_ARG0]);
	if (it_f != fdset.end())
		fdset.erase(it_f);
	else if(it_s != socketset.end())
	    socketset.erase(it_s);
	else
	    return;
}

/*
 * obtain the path of document by the fd
 */
static char* get_filepath(int fd_r)
{
    char buf[1024] = {'\0'};
	snprintf(buf,sizeof(buf), "/proc/self/fd/%d", fd_r);
	(void)readlink(buf,file_path,sizeof(file_path)-1);
	return file_path;
}

/*
 * read(2) and pread64(2) syscall post hook(source)
 *
 * tag the buffer of the sensitive documents relatively
 */
static void post_read_hook(THREADID tid, syscall_ctx_t *ctx)
{
    /* read() was not successful; optimized branch */
    if (unlikely((long)ctx->ret <= 0))
            return;
	/* taint-source (tag the buffer of the sensitive documents relatively) */
	//set中判断的都是系统调用的第一个参数，标签操作的是系统调用的第二个参数
	if (fdset.find((int)ctx->arg[SYSCALL_ARG0]) != fdset.end())
	{
	        char* file_path = get_filepath((int)ctx->arg[SYSCALL_ARG0]);
			if(strstr(file_path, PLAINTEXT_FILE) != NULL)
			//如果这个文件路径中有字符串"plaintext.txt"
			      /* set the tag markings */
	              tagmap_setn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret, TAG_PLAINTEXT);
		    else
			      /* set the tag markings */
	              tagmap_setn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret, TAG_KEY);	
	}
	else
        	/* clear the tag markings */
	        tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);
}

/*
 * readv(2) and preadv(2) syscall post hook(source)
 *
 * tag the buffer of the sensitive documents relatively
 */
static void post_readv_hook(THREADID tid, syscall_ctx_t *ctx)
{
	/* iterators */
	int i;
	struct iovec *iov;
	set<int>::iterator it;

	/* bytes copied in a iovec structure */
	size_t iov_tot;

	/* total bytes copied */
	size_t tot = (size_t)ctx->ret;

	/* readv() was not successful; optimized branch */
	if (unlikely((long)ctx->ret <= 0))
		return;
	
	/* get the descriptor */
	it = fdset.find((int)ctx->arg[SYSCALL_ARG0]);

	/* iterate the iovec structures */
	for (i = 0; i < (int)ctx->arg[SYSCALL_ARG2] && tot > 0; i++) 
	{
		/* get an iovec  */
		iov = ((struct iovec *)ctx->arg[SYSCALL_ARG1]) + i;
		
		/* get the length of the iovec */
		iov_tot = (tot >= (size_t)iov->iov_len) ?
			(size_t)iov->iov_len : tot;
	
		/* tag the buffer of the sensitive documents relatively */	
		if (it != fdset.end())
		{
	              char* file_path = get_filepath((int)ctx->arg[SYSCALL_ARG0]);
			      if(strstr(file_path, PLAINTEXT_FILE) != NULL)
			            /* set the tag markings */
	                    tagmap_setn((size_t)iov->iov_base, iov_tot, TAG_PLAINTEXT);
		          else
			            /* set the tag markings */
	                    tagmap_setn((size_t)iov->iov_base, iov_tot, TAG_KEY);	
	    }
		else
                	/* clear the tag markings */
                	tagmap_clrn((size_t)iov->iov_base, iov_tot);

        /* housekeeping */
        tot -= iov_tot;
    }
}

/*
 * write(2) and pwrite64(2) syscall pre hook(sink)
 *
 * if the buffer of these syscalls posess sensitive information, alert
 */
static void pre_write_hook(THREADID tid, syscall_ctx_t *ctx)
{
	if (socketset.find((int)ctx->arg[SYSCALL_ARG0]) != socketset.end())
	{
	    uint8_t tag = 0x00U;  /* record tag of the buffer */
	    for(uint8_t * k = (uint8_t *)ctx->arg[SYSCALL_ARG1] ; k <= (((uint8_t *)ctx->arg[SYSCALL_ARG1]) + ctx->arg[SYSCALL_ARG2]) ; k++)
	    {
	        tag |= tagmap_getb((size_t)k);
	    }
		if(tag > 0)
		    alert(ctx->arg[SYSCALL_ARG1] , ctx->arg[SYSCALL_ARG2] , tag);
	}
}

/*
 * writev(2)¡¢pwritev(2) syscall pre hook(sink)
 *
 * if the buffer of these syscalls posess sensitive information, alert
 */
static void pre_writev_hook(THREADID tid, syscall_ctx_t *ctx)
{
    /* get the descriptor */
	set<int>::iterator it;
	it = socketset.find((int)ctx->arg[SYSCALL_ARG0]);
	if (it != socketset.end())
	{
	    /* iterators */
	    int i;
	    struct iovec *iov;

	    /* bytes copied in a iovec structure */
	    size_t iov_tot;
	
	    uint8_t tag = 0x00U;

	    /* iterate the iovec structures */
	    for (i = 0; i < (int)ctx->arg[SYSCALL_ARG2]; i++) 
	    {
		    /* get an iovec  */
		    iov = ((struct iovec *)ctx->arg[SYSCALL_ARG1]) + i;
		
		    /* get the length of the iovec */
		    iov_tot = (size_t)iov->iov_len;
		
	        for(uint8_t * k = (uint8_t *)iov->iov_base ; k <= (((uint8_t *)iov->iov_base) + iov_tot) ; k++)
	        {
	            tag |= tagmap_getb((size_t)k);
	        }
		    if(tag > 0)
		        alert((ADDRINT)iov->iov_base , iov_tot , tag);	 
        }
	}
}

/*
 * sendto() syscall pre hook(sink)
 *
 * if the buffer of these syscalls posess sensitive information, alert
 */
static void pre_sendto_hook(THREADID tid, syscall_ctx_t *ctx)
{
	uint8_t tag = 0x00U;
	if (socketset.find((int)ctx->arg[SYSCALL_ARG0]) != socketset.end())
	{			
		for(uint8_t * k = (uint8_t *)ctx->arg[SYSCALL_ARG1] ; k <= (((uint8_t *)ctx->arg[SYSCALL_ARG1]) + ctx->arg[SYSCALL_ARG2]) ; k++)
	    {
	        tag |= tagmap_getb((size_t)k);
	    }
		if(tag > 0)
		   alert(ctx->arg[SYSCALL_ARG1] , ctx->arg[SYSCALL_ARG2] , tag);
	}

}

/* 
 * FDT
 */
int main(int argc, char **argv)
{
	/* initialize symbol processing */
	PIN_InitSymbols();
	
	if (unlikely(PIN_Init(argc, argv)))
		goto err;

	if (unlikely(libdft_init() != 0))
		goto err;
	
    /* 
	 * sinks
	 */
	
	/* instrument write(2) */
	(void)syscall_set_pre(&syscall_desc[__NR_write], pre_write_hook);
	
	/* instrument pwrite64(2)*/
	(void)syscall_set_pre(&syscall_desc[__NR_pwrite64], pre_write_hook);

	/* instrument writev(2) */
	(void)syscall_set_pre(&syscall_desc[__NR_writev], pre_writev_hook);
	
	/* instrument pwritev(2) */
	(void)syscall_set_pre(&syscall_desc[__NR_pwritev], pre_writev_hook);
	
	/* instrument sendto(2) */
	(void)syscall_set_pre(&syscall_desc[__NR_sendto], pre_sendto_hook);

	
	/* 
	 * sources
	 */

	/* instrument read(2) */
	(void)syscall_set_post(&syscall_desc[__NR_read], post_read_hook);
	
	/* instrument pread64(2) */
	(void)syscall_set_post(&syscall_desc[__NR_pread64], post_read_hook);

	/* instrument readv(2) */
	(void)syscall_set_post(&syscall_desc[__NR_readv], post_readv_hook);
	
	/* instrument preadv(2) */
	(void)syscall_set_post(&syscall_desc[__NR_preadv], post_readv_hook);
	

	/* instrument socket(2), accept(2) */
	(void)syscall_set_post(&syscall_desc[__NR_socket] , post_socket_hook);
    (void)syscall_set_post(&syscall_desc[__NR_accept] , post_accept_hook);
	/* instrument dup(2), dup2(2) */
	(void)syscall_set_post(&syscall_desc[__NR_dup], post_dup_hook);
	(void)syscall_set_post(&syscall_desc[__NR_dup2], post_dup_hook);

	/* instrument close(2) */
	(void)syscall_set_post(&syscall_desc[__NR_close], post_close_hook);
	
	/* instrument open(2) */
	(void)syscall_set_post(&syscall_desc[__NR_open] , post_open_hook);
	
	/* instrument openat(2) */
	(void)syscall_set_post(&syscall_desc[__NR_openat] , post_openat_hook);
	
	//socketset.insert(STDOUT_FILENO);
	/* Æô¶¯ Pin */
	PIN_StartProgram();

	return EXIT_SUCCESS;

err:	/* error handling */

	/* detach from the process */
	libdft_die();

	/* return */
	return EXIT_FAILURE;
}
