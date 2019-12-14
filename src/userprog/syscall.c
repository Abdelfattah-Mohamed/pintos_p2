#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "list.h"
#include "process.h"

static void syscall_handler (struct intr_frame *);
void* validation(const void*);
struct proc_file* get_file(struct list* files, int fd);
void check_buffer (void *buff_to_check, unsigned size);
void syscall_check_user_string(const char *ustr);

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
  //int * p = f->esp;

	validation((int *) f->esp);
	validation(f->esp + 3);



  //int system_call = * p;
	switch (*(int *) f->esp)
	{
		case SYS_HALT: {
			shutdown_power_off();
			break;	
		}
		
		case SYS_EXIT: {
			validation((int *) f->esp + 1);
			validation(f->esp + 7);
			exit(*((int *) f->esp + 1));
			break;	
		}
		
		case SYS_EXEC: {
			validation((int *) f->esp + 1);
			validation(f->esp + 7);
			validation(*((int *) f->esp + 1));
			syscall_check_user_string(*((int *) f->esp + 1));
			f->eax = excu(*((int *) f->esp + 1));
			break;
		}

		case SYS_WAIT:	{
			validation((int *) f->esp + 1);
			validation(f->esp + 7);
			f->eax = process_wait(*((int *) f->esp + 1));
			break;
		}
		
		case SYS_CREATE: {
			validation((int *) f->esp + 2);    // check second argument's address.
			validation(f->esp + 11);
	        validation(*((int *) f->esp + 1));    // check first argument's content.
	        syscall_check_user_string(*((int *) f->esp + 1));
	        check_buffer((void *) *((int *) f->esp + 1), *((int *) f->esp + 2));	
	        acquire_filesys_lock();    // Make sure only one process hold the file system at a time.
	        f->eax = filesys_create(*((int *) f->esp + 1),*((int *) f->esp + 2));	
	        release_filesys_lock();    // Release our lock.
			break;
		}
		case SYS_REMOVE: {
			validation((int *) f->esp + 1);    // check first argument's address.	
			validation(f->esp + 7);
	        validation(*((int *) f->esp + 1));    // check first argument's content.	
	        syscall_check_user_string(*((int *) f->esp + 1));
	        acquire_filesys_lock();    // Make sure only one process hold the file system at a time.	
	        if(!filesys_remove(*((int *) f->esp + 1))) f->eax = false;	
	        else f->eax = true;	
	        release_filesys_lock();    // Release our lock.
			break;
		}

		case SYS_OPEN: {
			int fd = -1;    // initialize file descriptor with invalid value.	
		    validation((int *) f->esp + 1);    // check first argument's address.
		    validation(f->esp + 7);	
		    validation(*((int *) f->esp + 1));    // check first argument's content.	
		    syscall_check_user_string(*((int *) f->esp + 1));
		    acquire_filesys_lock();    // Make sure only one process hold the file system at a time.	
		    //char *file = (char *) ;  // keep file name (argument[0]).	
		    struct file *of = filesys_open((*((int *) f->esp + 1)));   // open file.
		    release_filesys_lock();    // Release our lock.	
		    if (of != NULL) {	
		        // Create a struct to hold the file/fd.	
		    	struct proc_file *pf = malloc(sizeof(struct proc_file));	
		        pf->file = of;	
		        pf->fd = thread_current()->fd;  // generate fd for current file.	
		        thread_current()->fd++;   // Increment the fd for future files.	
		        // add file to file descriptors list in thread.	
		        list_push_back(&thread_current()->file_descriptors, &pf->elem);	
		        fd = pf->fd;	
		    }	
		    f->eax = fd;    // update f->eax with fd.	
		    break;
		}
		case SYS_FILESIZE: {
			validation((int *) f->esp + 1);    // check first argument's address.
			validation(f->esp + 7);
			acquire_filesys_lock();    // Make sure only one process hold the file system at a time.
			struct proc_file* pf =  malloc(sizeof(struct proc_file));
			pf = get_file(&thread_current()->file_descriptors, *((int *) f->esp + 1));   // get file.	
	        struct file *ff = pf->file;	
	        if (ff) f->eax = file_length(ff);  // get file length.	
	        else f->eax = -1;   // if not found.	
	        release_filesys_lock();    // Release our lock.
			break;
		}
		case SYS_READ:
		validation((int *) f->esp + 3);
		validation(f->esp + 15);
		validation(*((int *) f->esp + 2));
		check_buffer((void *) *((int *) f->esp + 2), *((int *) f->esp + 3));
		if(*((int *) f->esp + 1) == 0)
		{
			int i;
			uint8_t* buffer = *((int *) f->esp + 2);
			for(i=0;i<*((int *) f->esp + 3);i++)
				buffer[i] = input_getc();
			f->eax = *((int *) f->esp + 3);
		}
		else
		{
			struct proc_file* fptr = get_file(&thread_current()->file_descriptors, *((int *) f->esp + 1));
			if(fptr==NULL)
				f->eax=-1;
			else
			{
				acquire_filesys_lock();
				f->eax = file_read (fptr->file, *((int *) f->esp + 2), *((int *) f->esp + 3));
				release_filesys_lock();
			}
		}
		break;

		case SYS_WRITE:
		validation((int *) f->esp + 3);
		validation(f->esp + 15);
		validation(*((int *) f->esp + 2));
		check_buffer((void *) *((int *) f->esp + 2), *((int *) f->esp + 3));
		if(*((int *) f->esp + 1) == 1)
		{
			putbuf(*((int *) f->esp + 2), *((int *) f->esp + 3));
			f->eax = *((int *) f->esp + 3);
		}
		else
		{
			struct proc_file* fptr = get_file(&thread_current()->file_descriptors, *((int *) f->esp + 1));
			if(fptr==NULL)
				f->eax=-1;
			else
			{
				acquire_filesys_lock();
				f->eax = file_write (fptr->file, *((int *) f->esp + 2), *((int *) f->esp + 3));
				release_filesys_lock();
			}
		}
		break;

		case SYS_SEEK: {
			validation((int *) f->esp + 1);    // check first argument's address.	
			validation(f->esp + 7);
	        validation((int *) f->esp + 2);    // check second argument's address.	
	        validation(f->esp + 11);
	        acquire_filesys_lock();    // Make sure only one process hold the file system at a time.	
	        struct proc_file* pf = get_file(&thread_current()->file_descriptors, *((int *) f->esp + 1));	
	        struct file *ff = pf->file;   // get file.	
	        if (ff) file_seek(ff, *((int *) f->esp + 2));  // seek file.	
	        release_filesys_lock();    // Release our lock.
			break;
		}
		case SYS_TELL: {
			validation((int *) f->esp + 1);    // check first argument's address.	
			validation(f->esp + 7);
	        acquire_filesys_lock();    // Make sure only one process hold the file system at a time.
	        struct proc_file* pf = get_file(&thread_current()->file_descriptors, *((int *) f->esp + 1));   // get file.	
	        struct file *ff = pf->file;   // get file.	
	        if (ff) f->eax = file_tell(f);  // tell file.	
	        else f->eax = -1;
	        release_filesys_lock();   // Release our lock.
			break;
		}
		case SYS_CLOSE: {
			validation((int *) f->esp + 1);
			validation(f->esp + 7);
			acquire_filesys_lock();
			close_file(&thread_current()->file_descriptors, *((int *) f->esp + 1));
			release_filesys_lock();
			break;
		}

		default: {
			printf("Default %d\n", *(int *) f->esp);	
		}
	}
}

int excu(char *file_name)
{
	acquire_filesys_lock();
	char * fn_cp = malloc (strlen(file_name)+1);
	strlcpy(fn_cp, file_name, strlen(file_name)+1);
	  
	char * save_ptr;
	fn_cp = strtok_r(fn_cp," ",&save_ptr);

	struct file* f = filesys_open (fn_cp);

	if(f==NULL) {
		release_filesys_lock();
	  	return -1;
	} else {
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

void* validation(const void *vaddr)
{
  	if(!is_user_vaddr(vaddr) || vaddr == NULL || vaddr < (void *) 0x08048000 || pagedir_get_page(thread_current()->pagedir, vaddr) == NULL)
		exit(-1);
}

void check_buffer (void *buff_to_check, unsigned size)
{
  unsigned i;
  char *ptr  = (char * )buff_to_check;
  for (i = 0; i < size; i++)
    {
      validation((const void *) ptr);
      ptr++;
    }
}

struct proc_file* get_file(struct list* files, int fd)
{
	struct list_elem *e;
    for (e = list_begin (files); e != list_end (files); e = list_next (e)) {
        struct proc_file *f = list_entry (e, struct proc_file, elem);
        if(f->fd == fd) return f;
    }
   	return NULL;
}

void close_file(struct list* files, int fd)
{

	struct list_elem *temp;
	/* If there are no files in our file_descriptors list, return immediately, */
	if (!list_empty(&thread_current()->file_descriptors)) {
	  /* Look to see if the given fd is in our list of file_descriptors. If so, then we
	     close the file and remove it from our list of file_descriptors. */
		  for (temp = list_front(files); temp != NULL; temp = temp->next)
		  {
		      struct proc_file *t = list_entry (temp, struct proc_file, elem);
		      if (t->fd == fd)
		      {
		        file_close(t->file);
		        list_remove(&t->elem);
		        return;
		      }
		  }
	}
}

void close_all_files(struct list* files) {
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

void syscall_check_user_string(const char *ustr) {
  validation(ustr);

  int cnt = 0;
  while(*ustr != '\0'){
    if(cnt == 4095) exit(-1);
    cnt++;
    ustr++;
    if (((int)ustr & PGMASK) == 0){
      validation(ustr);
    }
  }
}