#include <iostream>
#include "pthread.h"
#include "stdio.h"

using namespace std;

class Container
{
	public:
		char * _a;
};
static Container test;

void* leak(void* ptr)
{
	for (int i = 0; i < 5; i++)
	{
		test._a = new char[1024 * 1024];
		cout << "new data base:" << std::hex << size_t(test._a) << endl;
		cout << "           at:" << std::hex << &test._a << endl;

	}

	Container c;
	c._a = new char[1024 * 1024];
	cout << "new data base:" << std::hex << size_t(c._a) << endl;
	cout << "           at:" << std::hex << &c._a << endl;
	char input = 0;

	for (int i = 0; i < 5; i++)
	{
		c._a = new char[1024 * 1024];
		cout << "new data base:" << std::hex << size_t(c._a) << endl;
		cout << "           at:" << std::hex << &c._a << endl;

	}

	cin >> input;	
	

	return 0;
}

int main()
{
	pthread_t tid;
	pthread_create(&tid, NULL, leak, NULL);

	pthread_join(tid, NULL);

	return 0;
}



