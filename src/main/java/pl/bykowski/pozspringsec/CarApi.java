package pl.bykowski.pozspringsec;

import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.Optional;

@RestController
public class CarApi {

    private ArrayList<Car> carArrayList;

    public CarApi() {
        carArrayList = new ArrayList<>();
        carArrayList.add(new Car(1, "BMW"));
        carArrayList.add(new Car(2, "FIAT"));
    }

    @GetMapping("/car")
    public ArrayList<Car> getCar() {
        return carArrayList;
    }

    @PostMapping("/car")
    public boolean addCar(@RequestBody Car car) {
        return carArrayList.add(car);
    }

    @DeleteMapping("/car")
    public boolean deleteCar(@RequestParam long id) {
        Optional<Car> first = carArrayList.stream().filter(element -> element.getId() == id).findFirst();
        if (first.isPresent()) {
            return carArrayList.remove(first.get());
        }
        return false;
    }


}
