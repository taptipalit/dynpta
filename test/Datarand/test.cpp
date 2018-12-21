#include <iostream>
#include <bits/stdc++.h>

class Student {
    public:
        std::string name;
        int id;

        void printName();

        void printId();

        void test(Student*);

        void add(int, int);
};

void Student::add(int a, int b) {
    std::cout << "Sum is: " << (a+b) << std::endl;
}

void Student::test(Student* studptr) {
    if (studptr->id == this->id) {
        std::cout << "Same!\n" << std::endl;
    } else {
        std::cout << "Not same!" << std::endl;
    }
}

void Student::printName(void) {
    std::cout<< "Name is : " << name << std::endl;
}

void Student::printId(void) {
    std::cout << "ID is : " << id << std::endl;
}

int main(void) {
    Student student;
    student.id = 1000;
    student.name = "Tapti";
    student.printName();
    student.printId();

    Student* sptr = new Student();
    sptr->id = 1000;
    sptr->name = "Santa";
    student.test(sptr);

    void (Student::*funcPtr) (int, int) = &Student::add;

    (student.*funcPtr)(3,4);
    return 0;
}

