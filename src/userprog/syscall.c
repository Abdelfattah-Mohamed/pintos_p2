#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "list.h"
#include "process.h"

static void syscall_handler (struct intr_frame *);
void *check_valid(const void *checker);
struct proc_file* get_file(struct list* files, int fd);

extern bool running;

struct proc_file {	
    struct file* file;	
    int fd;	
    struct list_elem elem;	
};

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	check_valid(f->esp);


	switch (*(int *) f->esp)
	{
		case SYS_HALT: {
			shutdown_power_off();
			break;
		}
		case SYS_EXIT: {
			check_valid((int *) f->esp + 1);
			exit(*((int *) f->esp + 1));
			break;
		}
		case SYS_EXEC:{
		check_valid((int *) f->esp + 1);
		check_valid(*((int *) f->esp + 1));
		f->eax = exec(*((int *) f->esp + 1));
		break;
}
		case SYS_WAIT:{
		check_valid((int *) f->esp + 1);
		f->eax = process_wait(*((int *) f->esp + 1));
		break;
}
		case SYS_CREATE:{
		acquire_filesys_lock();    // Make sure only one process hold the file system at a time.	
        check_valid((int *) f->esp + 2);    // check second argument's address.	
        check_valid(*((int *) f->esp + 1));    // check first argument's content.	
        f->eax = filesys_create(*((int *) f->esp + 1),*((int *) f->esp + 2));	
        release_filesys_lock();    // Release our lock.
		break;
}
		case SYS_REMOVE: {
		acquire_filesys_lock();    // Make sure only one process hold the file system at a time.	
        check_valid((int *) f->esp + 1);    // check first argument's address.	
        check_valid(*((int *) f->esp + 1));    // check first argument's content.	
         	
        if(!filesys_remove(*((int *) f->esp + 1))) f->eax = false;	
        else f->eax = true;	
        release_filesys_lock();    // Release our lock.
		break;
}
		case SYS_OPEN: {
		acquire_filesys_lock();    // Make sure only one process hold the file system at a time.	
        int fd = -1;    // initialize file descriptor with invalid value.	
        check_valid((int *) f->esp + 1);    // check first argument's address.	
        check_valid(*((int *) f->esp + 1));    // check first argument's content.	
        char *file = (char *) (*((int *) f->esp + 1));  // keep file name (argument[0]).	
        struct file *of = filesys_open(file);   // open file.	
        if (of) {	
            // Create a struct to hold the file/fd.	
        	struct proc_file *pf = malloc(sizeof(struct proc_file));	
            pf->file = f;	
            pf->fd = thread_current()->fd;  // generate fd for current file.	
            thread_current()->fd++;   // Increment the fd for future files.	
            // add file to file descriptors list in thread.	
            list_push_back(&thread_current()->file_descriptors, &pf->elem);	
            fd = pf->fd;	
        }	
        f->eax = fd;    // update f->eax with fd.	
        release_filesys_lock();    // Release our lock.	
        break;
}
		case SYS_FILESIZE: {
		acquire_filesys_lock();    // Make sure only one process hold the file system at a time.
		check_valid((int *) f->esp + 1);    // check first argument's address.	
		struct proc_file *pf = get_file(&thread_current()->file_descriptors, *((int *) f->esp + 1));   // get file.	
        struct file *ff = pf->file;	
        if (ff) f->eax = file_length(ff);  // get file length.	
        else f->eax = -1;   // if not found.	
        release_filesys_lock();    // Release our lock.
		break;
		}
		case SYS_READ: {
		check_valid((int *) f->esp + 3);
		check_valid(*((int *) f->esp + 2));
		if(*((int *) f->esp + 1) == 0)
		{
			int i;
			uint8_t* buffer = *((int *) f->esp + 2);
			for(i = 0; i < *((int *) f->esp + 3); i++)
				buffer[i] = input_getc();
			f->eax = *((int *) f->esp + 3);
		}
		else
		{
			struct proc_file* fptr = get_file(&thread_current()->file_descriptors, *((int *) f->esp + 1));
			if(fptr == NULL)
				f->eax = -1;
			else
			{
				acquire_filesys_lock();
				f->eax = file_read (fptr->file, *((int *) f->esp + 2), *((int *) f->esp + 3));
				release_filesys_lock();
			}
		}
		break;
}
		case SYS_WRITE: {
		check_valid((int *) f->esp + 3);
		check_valid(*((int *) f->esp + 2));
		if(*((int *) f->esp + 1) == 1)
		{
			putbuf(*((int *) f->esp + 2),*((int *) f->esp + 3));
			f->eax = *((int *) f->esp + 3);
		}
		else
		{
			struct proc_file* fptr = get_file(&thread_current()->file_descriptors, *((int *) f->esp + 1));
			if(fptr == NULL)
				f->eax = -1;
			else
			{
				acquire_filesys_lock();
				f->eax = file_write (fptr->file, *((int *) f->esp + 2), *((int *) f->esp + 3));
				release_filesys_lock();
			}
		}
		break;
}
		case SYS_SEEK: {
		acquire_filesys_lock();    // Make sure only one process hold the file system at a time.	
        check_valid((int *) f->esp + 1);    // check first argument's address.	
        check_valid((int *) f->esp + 2);    // check second argument's address.	
        struct proc_file* pf = get_file(&thread_current()->file_descriptors, *((int *) f->esp + 1));	
        struct file *ff = pf->file;   // get file.	
        if (ff) file_seek(ff, *((int *) f->esp + 2));  // seek file.	
        release_filesys_lock();    // Release our lock.
		break;
		}
		case SYS_TELL: {
		acquire_filesys_lock();    // Make sure only one process hold the file system at a time.	
        check_valid((int *) f->esp + 1);    // check first argument's address.	
        struct proc_file* pf = get_file(&thread_current()->file_descriptors, *((int *) f->esp + 1));   // get file.	
        struct file *ff = pf->file;   // get file.	
        if (ff) f->eax = file_tell(f);  // tell file.	
        else f->eax = -1;
        release_filesys_lock();   // Release our lock.
		break;
		}
		case SYS_CLOSE: {
		acquire_filesys_lock();    // Make sure only one process hold the file system at a time.	
        check_valid((int *) f->esp + 1);    // check first argument's address.	
        close_file(&thread_current()->file_descriptors, *((int *) f->esp + 1));  // close file.	
        release_filesys_lock();    // Release our lock.
		break;
}

		default:
		printf("Default %d\n",*((int *) f->esp + 1));
	}
}

int exec(char *file_name)
{
	acquire_filesys_lock();
	char * fn_cp = malloc (strlen(file_name)+1);
	  strlcpy(fn_cp, file_name, strlen(file_name)+1);
	  
	  char * save_ptr;
	  fn_cp = strtok_r(fn_cp," ",&save_ptr);

	 struct file* f = filesys_open (fn_cp);

	  if(f==NULL)
	  {
	  	release_filesys_lock();
	  	return -1;
	  }
	  else
	  {
	  	file_close(f);
	  	release_filesys_lock();
	  	return process_execute(file_name);
	  }
}

void exit(int status)
{
	struct list_elem *e;
      for (e = list_begin (&thread_current()->parent->children); e != list_end (&thread_current()->parent->children);
           e = list_next (e))
        {
          struct thread_child_data *f = list_entry (e, struct thread_child_data, elem);
          if(f->tid == thread_current()->tid)
          {
          	f->waited_on = true;
          	f->exit_status = status;
          }
        }

	thread_current()->exit_status = status;
	if(thread_current()->parent->waiting_on == thread_current()->tid)
		sema_up(&thread_current()->parent->child_lock);

	thread_exit();
}

void* check_valid(const void *vaddr)
{
	if (!is_user_vaddr(vaddr))
	{
		exit(-1);
		return 0;
	}
	void *file = pagedir_get_page(thread_current()->pagedir, vaddr);
	if (!file)
	{
		exit(-1);
		return 0;
	}
	return file;
}

struct proc_file* get_file(struct list* files, int fd)
{

	struct list_elem *e;

      for (e = list_begin (files); e != list_end (files);
           e = list_next (e))
        {
          struct proc_file *f = list_entry (e, struct proc_file, elem);
          if(f->fd == fd)
          	return f;
        }
   return NULL;
}

void close_file(struct list* files, int fd)
{

	struct list_elem *e;

	struct proc_file *f;

      for (e = list_begin (files); e != list_end (files);
           e = list_next (e))
        {
          f = list_entry (e, struct proc_file, elem);
          if(f->fd == fd)
          {
          	file_close(f->file);
          	list_remove(e);
          }
        }

    free(f);
}

void close_all_files(struct list* files)
{

	struct list_elem *e;

	while(!list_empty(files))
	{
		e = list_pop_front(files);

		struct proc_file *f = list_entry (e, struct proc_file, elem);
          
	      	file_close(f->file);
	      	list_remove(e);
	      	free(f);


	}

      
}