class A {
    Object fld;
}

class B {
    Object fld;
}

public class Store {
    public static void main(String[] args) {
        A a = new A();
        a.fld = new B();
        ((B) (a.fld)).fld = new A();
    }
}
