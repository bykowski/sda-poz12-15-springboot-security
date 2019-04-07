package pl.bykowski.pozspringsec;

public class Car {

    private long id;
    private String mark;

    public Car(long id, String mark) {
        this.id = id;
        this.mark = mark;
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public Car() {
    }

    public String getMark() {
        return mark;
    }

    public void setMark(String mark) {
        this.mark = mark;
    }
}
