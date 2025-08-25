
class A {}

class B {}

class C {
    Object id(Object v){
        return v;
    }
}


public class VirtualCall {
    public static void main(String[] args) {
        A a = new A();
        B b = new B();
        C c = new C();

        Object v1 = c.id(a);
        Object v2 = c.id(b);

        assert v1 != v2 : "v1 should not be the same object as v2";
    }
}
