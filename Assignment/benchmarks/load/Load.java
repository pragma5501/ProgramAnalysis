class A {
    Object fld;
}

class B {
    Object fld;
}

public class Load {
    public static void main(String[] args) {
        A a = new A();
        B b = new B();
        a.fld = b;
        b.fld = a;

        Object o1 = a.fld;
        Object o2 = b.fld;
        assert o1 != o2 : "o1 should not be the same object as o2";
    }
}
