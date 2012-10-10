#ifndef __pipe_h__
#define __pipe_h__

class named_pipe_t {

public:
	/* read from pipe */
	virtual int read( void* buffer, int nb );
	/* write to pipe */
	virtual int write( void* buffer, int nb );
public:
	/* close pipe */
	virtual void close() = 0;
public:
	named_pipe_t() : m_handle( 0 ) {}
	virtual ~named_pipe_t() {}
protected:
	void* m_handle;
};

class nmp_server_t : public named_pipe_t {

public:
	/* create server */
	virtual int create( const char* name );
	/* wait for clients */
	virtual int wait();
	/* close pipe */
	virtual void close();
public:
	~nmp_server_t() { close(); }
};

class nmp_client_t : public named_pipe_t {

public:
	/* connect to server */
	virtual int connect( const char* name );
	/* close pipe */
	virtual void close();
public:
	~nmp_client_t() { close(); }
};

#endif	/* !defined( __pipe_h__ ) */
