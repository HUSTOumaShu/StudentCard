package huy.tq204757.tutorial.model;

import jakarta.persistence.*;

@Entity
@Table(name = "tutorials")
public class Tutorial {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Column(name="title")
    private String title;
    @Column(name="description")
    private String description;
    @Column(name="published")
    private boolean isPublished;

    public Tutorial(String title, String description, boolean isPublished){
        this.title = title;
        this.description = description;
        this.isPublished = isPublished;
    }

    public void setId(Long id) { this.id = id; }
    public Long getId() { return id; }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public boolean isPublished() {
        return isPublished;
    }

    public void setPublished(boolean published) {
        isPublished = published;
    }

    @Override
    public String toString() {
        return "Tutorial [id=" + id + ", title=" + title +
                ", description=" + description + ", published=" + isPublished + "]";
    }
}
