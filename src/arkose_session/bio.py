import random
import math
import json
import base64
from typing import List, Dict, Tuple
import matplotlib.pyplot as plt


def perlin_noise_1d(x: float, persistence: float = 0.5, octaves: int = 4) -> float:
    total = 0
    frequency = 1
    amplitude = 1
    for _ in range(octaves):
        total += interpolated_noise(x * frequency) * amplitude
        frequency *= 2
        amplitude *= persistence
    return total


def interpolated_noise(x: float) -> float:
    integer_x = int(x)
    fractional_x = x - integer_x
    v1 = smooth_noise(integer_x)
    v2 = smooth_noise(integer_x + 1)
    return cosine_interpolate(v1, v2, fractional_x)


def smooth_noise(x: int) -> float:
    return math.sin(x * 0.1) * random.uniform(-0.5, 0.5)


def cosine_interpolate(a: float, b: float, x: float) -> float:
    ft = x * 3.1415927
    f = (1 - math.cos(ft)) * 0.5
    return a * (1 - f) + b * f



def clamp(x: float, lowerlimit: float, upperlimit: float) -> float:
    return max(lowerlimit, min(x, upperlimit))


class DataGenerator:
    def __init__(self):
        self.dPoints: List[Tuple[int, int]] = []
        self.timestamp: int = 0

    def binomial_coefficient(self, n: int, k: int) -> int:
        if k == 0 or k == n:
            return 1
        return self.binomial_coefficient(n - 1, k - 1) + self.binomial_coefficient(
            n - 1, k
        )

    def random_value(self, min_value: float, max_value: float) -> float:
        return random.uniform(min_value, max_value)

    def bezier_curve(
        self, points: List[Dict[str, float]], path: List[Dict[str, int]], timestamp: int
    ) -> int:
        num_points = len(points) - 1
        resolution = max(1, int(150 / len(self.dPoints) - self.random_value(0, 10)))
        
        last_x, last_y = points[0]["x"], points[0]["y"]
        last_timestamp = timestamp
        velocity = 0
        max_velocity = self.random_value(0.2, 0.8)
        acceleration = self.random_value(0.005, 0.03)
        deceleration = self.random_value(0.01, 0.04)
        jitter_factor = self.random_value(0.5, 1.2)
        pause_probability = self.random_value(0.05, 0.12)
        curve_deviation = self.random_value(0.5, 1.5)
        movement_style = self.random_value(0, 1)
        tremor_frequency = self.random_value(0.2, 0.5)
        overshoot_factor = self.random_value(0.1, 0.3)
        fatigue_factor = 1.0
        last_direction = None
        consecutive_moves = 0
        accuracy_factor = self.random_value(0.7, 1.3)
        target_offset = self.random_value(-5, 5)

        for i in range(resolution + 1):
            t = (i / resolution) ** curve_deviation

            x, y = 0, 0
            for j in range(num_points + 1):
                binomial = (
                    self.binomial_coefficient(num_points, j)
                    * (1 - t) ** (num_points - j)
                    * t**j
                )
                x += points[j]["x"] * binomial
                y += points[j]["y"] * binomial

            current_direction = math.atan2(y - last_y, x - last_x) if path else 0
            if last_direction is not None:
                direction_change = abs(current_direction - last_direction)
                if direction_change > math.pi/4:
                    fatigue_factor *= 0.9
                    consecutive_moves = 0
                else:
                    consecutive_moves += 1
                    if consecutive_moves > 3:
                        fatigue_factor *= 0.95
            last_direction = current_direction

            base_jitter = self.random_value(-2, 2) * jitter_factor
            tremor = math.sin(timestamp * tremor_frequency) * self.random_value(0.3, 0.8)
            jitter_x = base_jitter + tremor
            jitter_y = base_jitter + tremor
            x += jitter_x * accuracy_factor
            y += jitter_y * accuracy_factor

            if path:
                dx = x - last_x
                dy = y - last_y
                distance = math.sqrt(dx**2 + dy**2)

                if distance > 0.1:
                    if velocity < max_velocity:
                        accel_factor = 1 + self.random_value(-0.4, 0.4)
                        if movement_style < 0.3:
                            accel_factor *= 1.3
                        elif movement_style > 0.7:
                            accel_factor *= 0.7
                        velocity += acceleration * accel_factor * fatigue_factor
                    else:
                        decel_factor = 1 + self.random_value(-0.3, 0.3)
                        velocity -= deceleration * decel_factor * fatigue_factor
                    
                    velocity = max(0.05, min(velocity, max_velocity))
                    
                    time_delta = int(distance / velocity)
                    time_delta = max(5, min(time_delta, 45))
                    
                    if self.random_value(0, 1) < pause_probability:
                        pause_duration = int(self.random_value(30, 250))
                        if consecutive_moves > 5:
                            pause_duration *= 1.8
                        time_delta += pause_duration
                    
                    if self.random_value(0, 1) < 0.2:
                        micro_pause = int(self.random_value(5, 20))
                        time_delta += micro_pause
                    
                    if self.random_value(0, 1) < 0.15 and distance > 3:
                        overshoot_x = dx * overshoot_factor * (1 + self.random_value(-0.2, 0.2))
                        overshoot_y = dy * overshoot_factor * (1 + self.random_value(-0.2, 0.2))
                        x += overshoot_x
                        y += overshoot_y
                        time_delta += int(self.random_value(10, 30))
                    
                    if self.random_value(0, 1) < 0.1:
                        x += target_offset
                        y += target_offset
                    
                    timestamp += time_delta
                    path.append(
                        {"timestamp": int(timestamp), "type": 0, "x": int(x), "y": int(y)}
                    )
                    
                    last_x, last_y = x, y
                    last_timestamp = timestamp
            else:
                initial_pause = int(self.random_value(50, 250))
                if movement_style > 0.8:
                    initial_pause *= 2
                timestamp += initial_pause
                path.append(
                    {"timestamp": int(timestamp), "type": 0, "x": int(x), "y": int(y)}
                )
                last_x, last_y = x, y
                last_timestamp = timestamp

        return timestamp

    def generate_random_points(self, index: int) -> List[Dict[str, float]]:
        start = [700, 200] if index == 0 else self.dPoints[index - 1]
        end = self.dPoints[index]

        midpoint_x = (start[0] + end[0]) / 2
        noise_scale = 0.17
        noise_offset = perlin_noise_1d(index * noise_scale) * 210
        midpoint_y = (start[1] + end[1]) / 2 + self.random_value(0, 210) + noise_offset

        return [
            {"x": start[0], "y": start[1]},
            {"x": midpoint_x, "y": midpoint_y},
            {"x": end[0], "y": end[1]},
        ]

    def generate_motion_data(self) -> List[Dict[str, int]]:
        self.timestamp = int(self.random_value(0, 70))
        motion_curve_data: List[Dict[str, int]] = []

        for i in range(len(self.dPoints)):
            control_points = self.generate_random_points(i)
            self.timestamp = self.bezier_curve(
                control_points, motion_curve_data, self.timestamp
            )

        # print(motion_curve_data)
        return motion_curve_data

    def generate_motion_data_str(self) -> str:
        self.timestamp = int(self.random_value(0, 70))

    def generate_key_data(self) -> str:
        self.timestamp = int(self.random_value(0, 70))
        key_curve_data: List[Dict[str, int]] = []

        for _ in range(int(self.random_value(25, 50))):
            self.timestamp += int(self.random_value(1000, 5010))
            key_curve_data.append(
                {
                    "timestamp": self.timestamp,
                    "type": int(self.random_value(1, 3)),
                    "extra": 0,
                }
            )

        return ";".join(
            f"{p['timestamp']},{p['type']},{p['extra']}" for p in key_curve_data
        )

    def generate_d_points(self) -> List[Tuple[int, int]]:
        self.dPoints = []
        for _ in range(int(self.random_value(3, 6))):
            x, y = int(self.random_value(700, 1320)), int(self.random_value(300, 700))
            self.dPoints.append((x, y))
        return self.dPoints

    def generate(self) -> str:
        self.dPoints = self.generate_d_points()
        motion_data = self.generate_motion_data()
        key_data = self.generate_key_data()

        data = {"mbio": motion_data, "tbio": "", "kbio": key_data}

        data_json = json.dumps(data, separators=(",", ":"))
        return base64.b64encode(data_json.encode("utf-8")).decode("utf-8")


def convert_list_to_str(list_of_dicts):
    """Converts a list of dictionaries to a CSV-formatted string.

    Args:
      list_of_dicts: A list of dictionaries, where each dictionary
                     should contain 'timestamp', 'type', 'x', and 'y' keys.

    Returns:
      A CSV string representation of the data. Returns an error message if the input is invalid.
    """
    if not isinstance(list_of_dicts, list):
        return "Error: Input must be a list of dictionaries."

    required_keys = {"timestamp", "type", "x", "y"}
    for item in list_of_dicts:
        if not isinstance(item, dict) or not required_keys.issubset(item.keys()):
            return "Error: Dictionaries must contain 'timestamp', 'type', 'x', and 'y' keys."

    movement: str = ""
    for item in list_of_dicts:
        movement += f"{item['timestamp']},{item['type']},{item['x']},{item['y']};"
    return movement


if __name__ == "__main__":
    generator = DataGenerator()
    generator.generate_d_points()
    motion_data = generator.generate_motion_data()
    print(motion_data)

    print(convert_list_to_str(motion_data))

    plot = plt.plot([i["x"] for i in motion_data], [i["y"] for i in motion_data])
    plt.show()